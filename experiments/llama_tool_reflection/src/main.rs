use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fmt::{self, Display};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SUBJECT: &str = "bank";
const PURPOSE: &str = "decide where to deposit a paycheck";
const SELECTED_IDENTITY: &str = "financial_institution";
const EXCLUDED_IDENTITY: &str = "river_bank";
const NEXT_ACTION: &str = "compare_account_options";
const SOURCE_ADDRESS: &str = "fixture://bank/paycheck-deposit";
const STYLES: [&str; 3] = ["verbose", "condensed", "directive"];

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
struct Config {
    base_url: String,
    model: String,
    output: PathBuf,
    timeout: Duration,
}

impl Config {
    fn parse() -> Result<Self, AnyError> {
        let mut base_url = "http://127.0.0.1:8080/v1".to_owned();
        let mut model = "gpt-oss-20b".to_owned();
        let mut output = PathBuf::from("experiments/llama_tool_reflection/artifacts/latest.json");
        let mut timeout = Duration::from_secs(180);
        let mut args = env::args().skip(1);

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--base-url" => {
                    base_url = required_value(&mut args, "--base-url")?;
                }
                "--model" => {
                    model = required_value(&mut args, "--model")?;
                }
                "--output" => {
                    output = PathBuf::from(required_value(&mut args, "--output")?);
                }
                "--timeout-seconds" => {
                    let value = required_value(&mut args, "--timeout-seconds")?;
                    timeout = Duration::from_secs(value.parse()?);
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            model,
            output,
            timeout,
        })
    }
}

fn required_value(
    args: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, AnyError> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value").into())
}

fn print_help() {
    println!(
        "cantor-llama-tool-reflection\n\
         \n\
         Runs a bounded two-checkpoint llama.cpp tool-use probe.\n\
         \n\
         Options:\n\
           --base-url URL       OpenAI-compatible API root (default: http://127.0.0.1:8080/v1)\n\
           --model NAME         API model alias (default: gpt-oss-20b)\n\
           --output PATH        Sanitized JSON trace path\n\
           --timeout-seconds N  Per-request timeout (default: 180)"
    );
}

#[derive(Debug)]
struct ProbeFault {
    kind: &'static str,
    message: String,
}

impl ProbeFault {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl Display for ProbeFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.kind, self.message)
    }
}

impl Error for ProbeFault {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ToolArguments {
    subject: String,
    purpose: String,
    expression_style: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolResult {
    expression_style: String,
    semantic_expression: String,
    source_address: String,
    authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InferenceImportResult {
    selected_identity: String,
    excluded_identity: String,
    purpose: String,
    next_action: String,
    expression_style: String,
    source_address: String,
}

impl InferenceImportResult {
    fn semantic_key(&self) -> (&str, &str, &str, &str, &str) {
        (
            &self.selected_identity,
            &self.excluded_identity,
            &self.purpose,
            &self.next_action,
            &self.source_address,
        )
    }
}

#[derive(Debug, Serialize)]
struct TrialRecord {
    expression_style: String,
    status: String,
    fault: Option<String>,
    fault_detail: Option<String>,
    host_elapsed_ms: u128,
    first_request: Value,
    first_response: Option<Value>,
    first_request_elapsed_ms: Option<u128>,
    tool_call: Option<Value>,
    tool_result: Option<ToolResult>,
    second_request: Option<Value>,
    second_response: Option<Value>,
    second_request_elapsed_ms: Option<u128>,
    normalized_result: Option<InferenceImportResult>,
}

impl TrialRecord {
    fn new(expression_style: &str, first_request: Value) -> Self {
        Self {
            expression_style: expression_style.to_owned(),
            status: "failed".to_owned(),
            fault: None,
            fault_detail: None,
            host_elapsed_ms: 0,
            first_request,
            first_response: None,
            first_request_elapsed_ms: None,
            tool_call: None,
            tool_result: None,
            second_request: None,
            second_response: None,
            second_request_elapsed_ms: None,
            normalized_result: None,
        }
    }

    fn fail(&mut self, fault: ProbeFault, started: Instant) {
        self.fault = Some(fault.kind.to_owned());
        self.fault_detail = Some(fault.message);
        self.host_elapsed_ms = started.elapsed().as_millis();
    }
}

struct ToolInvocation {
    assistant_message: Value,
    tool_call: Value,
    call_id: String,
    arguments: ToolArguments,
}

fn main() -> ExitCode {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration_fault: {error}");
            return ExitCode::from(2);
        }
    };

    let started_ms = unix_time_ms();
    let client = match Client::builder().timeout(config.timeout).build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("client_fault: {error}");
            return ExitCode::from(2);
        }
    };

    let report = run_probe(&client, &config, started_ms);
    let passed = report
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "passed");

    if let Some(parent) = config.output.parent()
        && let Err(error) = fs::create_dir_all(parent)
    {
        eprintln!("trace_fault: cannot create {}: {error}", parent.display());
        return ExitCode::from(2);
    }

    let encoded = match serde_json::to_string_pretty(&report) {
        Ok(encoded) => encoded,
        Err(error) => {
            eprintln!("trace_fault: cannot serialize report: {error}");
            return ExitCode::from(2);
        }
    };

    if let Err(error) = fs::write(&config.output, encoded) {
        eprintln!(
            "trace_fault: cannot write {}: {error}",
            config.output.display()
        );
        return ExitCode::from(2);
    }

    println!(
        "{}: sanitized trace written to {}",
        if passed { "PASS" } else { "FAIL" },
        config.output.display()
    );
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_probe(client: &Client, config: &Config, started_ms: u128) -> Value {
    let props_url = format!(
        "{}/props",
        config
            .base_url
            .strip_suffix("/v1")
            .unwrap_or(&config.base_url)
    );
    let props_result = get_json(client, &props_url);
    let (server_summary, server_fault) = match props_result {
        Ok((props, elapsed)) => (
            json!({
                "status": "reachable",
                "elapsed_ms": elapsed,
                "chat_template_present": props
                    .get("chat_template")
                    .and_then(Value::as_str)
                    .is_some_and(|template| !template.is_empty()),
                "chat_template_characters": props
                    .get("chat_template")
                    .and_then(Value::as_str)
                    .map(str::len),
                "model_path": props
                    .pointer("/default_generation_settings/model")
                    .or_else(|| props.get("model_path"))
                    .cloned(),
                "total_slots": props.get("total_slots").cloned(),
            }),
            None,
        ),
        Err(fault) => (
            json!({
                "status": "unavailable",
                "endpoint": props_url,
            }),
            Some(fault),
        ),
    };

    if let Some(fault) = server_fault {
        return json!({
            "probe": "cantor_llama_cpp_tool_reflection",
            "contract": "Cantor_Llama_CPP_Tool_Reflection_Probe.sop",
            "provider": "llama.cpp",
            "base_url": config.base_url,
            "model": config.model,
            "started_unix_ms": started_ms,
            "finished_unix_ms": unix_time_ms(),
            "status": "failed",
            "fault": "server_unavailable",
            "fault_detail": fault.to_string(),
            "server": server_summary,
            "private_reasoning_recorded": false,
            "trials": [],
        });
    }

    let mut trials = Vec::new();
    for style in STYLES {
        trials.push(run_trial(client, config, style));
    }

    let expressions: Vec<&str> = trials
        .iter()
        .filter_map(|trial| {
            trial
                .tool_result
                .as_ref()
                .map(|result| result.semantic_expression.as_str())
        })
        .collect();
    let expression_set: HashSet<&str> = expressions.iter().copied().collect();
    let surface_forms_are_distinct =
        expressions.len() == STYLES.len() && expression_set.len() == STYLES.len();

    let normalized: Vec<&InferenceImportResult> = trials
        .iter()
        .filter_map(|trial| trial.normalized_result.as_ref())
        .collect();
    let cross_style_semantic_equal = normalized.len() == STYLES.len()
        && normalized
            .windows(2)
            .all(|pair| pair[0].semantic_key() == pair[1].semantic_key());

    let all_trials_pass = trials.iter().all(|trial| trial.status == "passed");
    let passed = all_trials_pass && surface_forms_are_distinct && cross_style_semantic_equal;

    json!({
        "probe": "cantor_llama_cpp_tool_reflection",
        "contract": "Cantor_Llama_CPP_Tool_Reflection_Probe.sop",
        "provider": "llama.cpp",
        "base_url": config.base_url,
        "model": config.model,
        "started_unix_ms": started_ms,
        "finished_unix_ms": unix_time_ms(),
        "status": if passed { "passed" } else { "failed" },
        "server": server_summary,
        "surface_forms_are_distinct": surface_forms_are_distinct,
        "cross_style_semantic_equal": cross_style_semantic_equal,
        "private_reasoning_recorded": false,
        "trials": trials,
    })
}

fn run_trial(client: &Client, config: &Config, style: &str) -> TrialRecord {
    let trial_started = Instant::now();
    let first_request = first_request(&config.model, style);
    let mut record = TrialRecord::new(style, first_request.clone());

    let (first_response, first_elapsed) = match post_json(
        client,
        &format!("{}/chat/completions", config.base_url),
        &first_request,
    ) {
        Ok(response) => response,
        Err(fault) => {
            record.fail(fault, trial_started);
            return record;
        }
    };
    record.first_request_elapsed_ms = Some(first_elapsed);
    record.first_response = Some(sanitize_response(&first_response));

    let invocation = match extract_tool_invocation(&first_response, style) {
        Ok(invocation) => invocation,
        Err(fault) => {
            record.fail(fault, trial_started);
            return record;
        }
    };
    record.tool_call = Some(invocation.tool_call.clone());

    let tool_result = reflect(&invocation.arguments);
    record.tool_result = Some(tool_result.clone());

    let second_request = second_request(
        &config.model,
        &invocation.assistant_message,
        &invocation.call_id,
        &tool_result,
        style,
    );
    record.second_request = Some(second_request.clone());

    let (second_response, second_elapsed) = match post_json(
        client,
        &format!("{}/chat/completions", config.base_url),
        &second_request,
    ) {
        Ok(response) => response,
        Err(fault) => {
            record.fail(fault, trial_started);
            return record;
        }
    };
    record.second_request_elapsed_ms = Some(second_elapsed);
    record.second_response = Some(sanitize_response(&second_response));

    let normalized = match extract_import_result(&second_response, style) {
        Ok(result) => result,
        Err(fault) => {
            record.fail(fault, trial_started);
            return record;
        }
    };

    record.normalized_result = Some(normalized);
    record.status = "passed".to_owned();
    record.host_elapsed_ms = trial_started.elapsed().as_millis();
    record
}

fn first_request(model: &str, style: &str) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are executing a controlled tool-interface test. Do not answer the semantic request directly. Call cantor_reflect exactly once. Copy the subject, purpose, and requested expression_style exactly into its arguments. After its result is supplied, import that result and return only the requested normalized JSON. Do not invent or alter semantic identities."
            },
            {
                "role": "user",
                "content": format!(
                    "Reflect subject \"{SUBJECT}\" for purpose \"{PURPOSE}\" using expression_style \"{style}\"."
                )
            }
        ],
        "tools": [cantor_reflect_tool_schema()],
        "tool_choice": "required",
        "parallel_tool_calls": false,
        "temperature": 0,
        "max_tokens": 512
    })
}

fn second_request(
    model: &str,
    assistant_message: &Value,
    call_id: &str,
    tool_result: &ToolResult,
    style: &str,
) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are executing a controlled tool-interface test. Import the supplied cantor_reflect result. Return only one JSON object with exactly these six fields: selected_identity, excluded_identity, purpose, next_action, expression_style, source_address. Derive selected_identity, excluded_identity, and next_action from semantic_expression. Copy purpose, expression_style, and source_address exactly. Do not return semantic_expression, authority, or subject. Do not call a tool again."
            },
            {
                "role": "user",
                "content": format!(
                    "Reflect subject \"{SUBJECT}\" for purpose \"{PURPOSE}\" using expression_style \"{style}\"."
                )
            },
            assistant_message,
            {
                "role": "tool",
                "tool_call_id": call_id,
                "content": serde_json::to_string(tool_result)
                    .expect("serializing a fixed ToolResult cannot fail")
            },
            {
                "role": "user",
                "content": "Checkpoint 2: treat the preceding tool result as semantic evidence, not as the final response. Import it now as selected_identity, excluded_identity, purpose, next_action, expression_style, and source_address. Return exactly those fields; do not repeat semantic_expression or authority."
            }
        ],
        "tools": [cantor_reflect_tool_schema()],
        "tool_choice": "none",
        "parallel_tool_calls": false,
        "response_format": {
            "type": "json_schema",
            "schema": import_result_schema()
        },
        "temperature": 0,
        "max_tokens": 512
    })
}

fn cantor_reflect_tool_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "cantor_reflect",
            "description": "Resolve one contextual semantic subject into a requested expression style.",
            "parameters": {
                "type": "object",
                "additionalProperties": false,
                "required": ["subject", "purpose", "expression_style"],
                "properties": {
                    "subject": {
                        "type": "string",
                        "const": SUBJECT
                    },
                    "purpose": {
                        "type": "string",
                        "const": PURPOSE
                    },
                    "expression_style": {
                        "type": "string",
                        "enum": STYLES
                    }
                }
            }
        }
    })
}

fn import_result_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "selected_identity",
            "excluded_identity",
            "purpose",
            "next_action",
            "expression_style",
            "source_address"
        ],
        "properties": {
            "selected_identity": {
                "type": "string",
                "const": SELECTED_IDENTITY
            },
            "excluded_identity": {
                "type": "string",
                "const": EXCLUDED_IDENTITY
            },
            "purpose": {
                "type": "string",
                "const": PURPOSE
            },
            "next_action": {
                "type": "string",
                "const": NEXT_ACTION
            },
            "expression_style": {
                "type": "string",
                "enum": STYLES
            },
            "source_address": {
                "type": "string",
                "const": SOURCE_ADDRESS
            }
        }
    })
}

fn extract_tool_invocation(
    response: &Value,
    expected_style: &str,
) -> Result<ToolInvocation, ProbeFault> {
    let message = response
        .pointer("/choices/0/message")
        .ok_or_else(|| ProbeFault::new("provider_fault", "missing choices[0].message"))?;
    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeFault::new("tool_not_called", "response has no tool_calls array"))?;

    if calls.is_empty() {
        return Err(ProbeFault::new(
            "tool_not_called",
            "model returned no tool call",
        ));
    }
    if calls.len() != 1 {
        return Err(ProbeFault::new(
            "argument_fault",
            format!("expected exactly one tool call, received {}", calls.len()),
        ));
    }

    let call = &calls[0];
    let name = call
        .pointer("/function/name")
        .and_then(Value::as_str)
        .ok_or_else(|| ProbeFault::new("wrong_tool", "tool call has no function name"))?;
    if name != "cantor_reflect" {
        return Err(ProbeFault::new(
            "wrong_tool",
            format!("expected cantor_reflect, received {name}"),
        ));
    }

    let call_id = call
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| ProbeFault::new("provider_fault", "tool call has no id"))?
        .to_owned();
    let raw_arguments = call
        .pointer("/function/arguments")
        .ok_or_else(|| ProbeFault::new("argument_fault", "tool call has no arguments"))?;
    let argument_value = match raw_arguments {
        Value::String(encoded) => serde_json::from_str(encoded).map_err(|error| {
            ProbeFault::new(
                "argument_fault",
                format!("tool arguments are not valid JSON: {error}"),
            )
        })?,
        Value::Object(_) => raw_arguments.clone(),
        _ => {
            return Err(ProbeFault::new(
                "argument_fault",
                "tool arguments must be a JSON object or encoded JSON object",
            ));
        }
    };
    let arguments: ToolArguments = serde_json::from_value(argument_value).map_err(|error| {
        ProbeFault::new(
            "argument_fault",
            format!("tool arguments violate the contract: {error}"),
        )
    })?;

    let expected = ToolArguments {
        subject: SUBJECT.to_owned(),
        purpose: PURPOSE.to_owned(),
        expression_style: expected_style.to_owned(),
    };
    if arguments != expected {
        return Err(ProbeFault::new(
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
        call_id,
        arguments,
    })
}

fn reflect(arguments: &ToolArguments) -> ToolResult {
    let semantic_expression = match arguments.expression_style.as_str() {
        "verbose" => format!(
            "For the purpose \"{PURPOSE}\", interpret \"{SUBJECT}\" as the identity \
             \"{SELECTED_IDENTITY}\". Exclude the competing identity \
             \"{EXCLUDED_IDENTITY}\". The next action is \"{NEXT_ACTION}\"."
        ),
        "condensed" => format!(
            "SUBJECT {SUBJECT} | PURPOSE {PURPOSE} | SELECT {SELECTED_IDENTITY} | \
             EXCLUDE {EXCLUDED_IDENTITY} | NEXT {NEXT_ACTION}"
        ),
        "directive" => format!(
            "OBSERVE subject={SUBJECT}; NAME selected_identity={SELECTED_IDENTITY}; \
             EXCLUDE excluded_identity={EXCLUDED_IDENTITY}; BOUND purpose=\"{PURPOSE}\"; \
             EMIT next_action={NEXT_ACTION}"
        ),
        _ => unreachable!("validated expression_style"),
    };

    ToolResult {
        expression_style: arguments.expression_style.clone(),
        semantic_expression,
        source_address: SOURCE_ADDRESS.to_owned(),
        authority: "test_fixture_only".to_owned(),
    }
}

fn extract_import_result(
    response: &Value,
    expected_style: &str,
) -> Result<InferenceImportResult, ProbeFault> {
    let message = response
        .pointer("/choices/0/message")
        .ok_or_else(|| ProbeFault::new("provider_fault", "missing choices[0].message"))?;
    if message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
    {
        return Err(ProbeFault::new(
            "tool_loop",
            "second inference emitted another tool call",
        ));
    }

    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| ProbeFault::new("schema_fault", "second inference has no text content"))?;
    let result: InferenceImportResult = serde_json::from_str(content).map_err(|error| {
        ProbeFault::new(
            "schema_fault",
            format!("second inference is not valid contract JSON: {error}"),
        )
    })?;

    let expected = InferenceImportResult {
        selected_identity: SELECTED_IDENTITY.to_owned(),
        excluded_identity: EXCLUDED_IDENTITY.to_owned(),
        purpose: PURPOSE.to_owned(),
        next_action: NEXT_ACTION.to_owned(),
        expression_style: expected_style.to_owned(),
        source_address: SOURCE_ADDRESS.to_owned(),
    };
    if result != expected {
        return Err(ProbeFault::new(
            "semantic_fault",
            format!("expected {expected:?}, received {result:?}"),
        ));
    }

    Ok(result)
}

fn post_json(client: &Client, url: &str, body: &Value) -> Result<(Value, u128), ProbeFault> {
    let started = Instant::now();
    let response = client
        .post(url)
        .json(body)
        .send()
        .map_err(|error| ProbeFault::new("provider_fault", error.to_string()))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|error| ProbeFault::new("provider_fault", error.to_string()))?;
    let elapsed = started.elapsed().as_millis();

    if !status.is_success() {
        return Err(ProbeFault::new(
            "provider_fault",
            format!("HTTP {status}: {}", truncate(&text, 2_000)),
        ));
    }

    let value = serde_json::from_str(&text).map_err(|error| {
        ProbeFault::new(
            "provider_fault",
            format!(
                "response is not JSON: {error}; body={}",
                truncate(&text, 2_000)
            ),
        )
    })?;
    Ok((value, elapsed))
}

fn get_json(client: &Client, url: &str) -> Result<(Value, u128), ProbeFault> {
    let started = Instant::now();
    let response = client
        .get(url)
        .send()
        .map_err(|error| ProbeFault::new("server_unavailable", error.to_string()))?;
    let status = response.status();
    let text = response
        .text()
        .map_err(|error| ProbeFault::new("server_unavailable", error.to_string()))?;
    let elapsed = started.elapsed().as_millis();

    if !status.is_success() {
        return Err(ProbeFault::new(
            "server_unavailable",
            format!("HTTP {status}: {}", truncate(&text, 2_000)),
        ));
    }
    let value = serde_json::from_str(&text).map_err(|error| {
        ProbeFault::new(
            "server_unavailable",
            format!("properties response is not JSON: {error}"),
        )
    })?;
    Ok((value, elapsed))
}

fn sanitize_response(response: &Value) -> Value {
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

fn truncate(value: &str, maximum_characters: usize) -> String {
    value.chars().take(maximum_characters).collect()
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
