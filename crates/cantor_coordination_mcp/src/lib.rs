//! Stateless MCP transport for Cantor's resumable coordination stepper.
//!
//! Complete admitted context and checkpoint state travel through each call.
//! The adapter stores nothing and delegates all semantics to the pure
//! provider-neutral dispatcher.

#![recursion_limit = "512"]

use std::sync::Arc;

use cantor_procedure_tool::{
    CoordinationToolOperation, CoordinationToolRequest, CoordinationToolResponse,
    execute_coordination_tool_request,
};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestMethod, CallToolRequestParams, CallToolResponse, CallToolResult,
        ContentBlock, Implementation, JsonObject, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
    },
    service::{RequestContext, RoleServer},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const TOOL_NAME: &str = "step_procedure_coordination";
pub const ADAPTER_PROFILE: &str = "cantor-coordination-mcp/0.1";
pub const MAX_ARGUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const SERVER_INSTRUCTIONS: &str = "Use step_procedure_coordination only between inference passes. BEGIN requires the complete exact admitted context. ADVANCE requires that same context, one checkpoint, and a positive finite step quota. Preserve structuredContent exactly. This server stores no context or checkpoint, invokes no model, shares no hidden state, grants no effect authority, and does not authenticate checkpoint producers.";

#[derive(Clone, Debug, Default)]
pub struct CoordinationMcpServer;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepProcedureCoordinationArguments {
    pub request: CoordinationToolRequest,
}

impl CoordinationMcpServer {
    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Begin or advance one bounded deterministic Cantor procedure-coordination checkpoint. Supply complete admitted context on every call; the tool retains no state and performs no external effect.",
            input_schema(),
        )
        .with_title("Step Cantor procedure coordination")
        .with_raw_output_schema(Arc::new(output_schema()))
        .with_annotations(
            ToolAnnotations::with_title("Step Cantor procedure coordination")
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
    }

    pub fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let value = Value::Object(arguments.unwrap_or_default());
        let operation = operation_hint(&value);
        let encoded_length = match serde_json::to_vec(&value) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                return response_result(CoordinationToolResponse::internal(
                    operation,
                    "argument_encoding_failed",
                    bounded(&error.to_string()),
                ));
            }
        };
        if encoded_length > MAX_ARGUMENT_BYTES {
            return response_result(CoordinationToolResponse::invalid(
                operation,
                "argument_limit_exceeded",
                format!(
                    "tool arguments contain {encoded_length} bytes; maximum is {MAX_ARGUMENT_BYTES}"
                ),
            ));
        }
        let parsed: StepProcedureCoordinationArguments = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return response_result(CoordinationToolResponse::invalid(
                    operation,
                    "invalid_arguments",
                    bounded(&error.to_string()),
                ));
            }
        };
        response_result(execute_coordination_tool_request(parsed.request))
    }
}

impl ServerHandler for CoordinationMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-coordination", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor resumable procedure coprocessor")
                    .with_description(
                        "Stateless bounded execution-frame stepping through one typed tool.",
                    ),
            )
            .with_instructions(SERVER_INSTRUCTIONS)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        (name == TOOL_NAME).then(Self::tool_definition)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![
            Self::tool_definition(),
        ]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if request.name != TOOL_NAME {
            return Err(McpError::method_not_found::<CallToolRequestMethod>());
        }
        Ok(self.execute_tool_arguments(request.arguments).into())
    }
}

fn response_result(response: CoordinationToolResponse) -> CallToolResult {
    let (value, is_error) = match serde_json::to_value(&response) {
        Ok(value) => (value, response.is_error()),
        Err(error) => {
            let fallback = CoordinationToolResponse::internal(
                CoordinationToolOperation::Unavailable,
                "response_encoding_failed",
                bounded(&error.to_string()),
            );
            (
                serde_json::to_value(fallback).unwrap_or_else(|_| {
                    json!({
                        "profile": ADAPTER_PROFILE,
                        "operation": "unavailable",
                        "status": "internal_fault",
                        "result": null,
                        "fault": {
                            "code": "response_encoding_failed",
                            "category": "internal_fault",
                            "message": "coordination response serialization failed"
                        },
                        "nonclaims": []
                    })
                }),
                true,
            )
        }
    };
    let status = value["status"].as_str().unwrap_or("internal_fault");
    let operation = value["operation"].as_str().unwrap_or("unavailable");
    let content = vec![ContentBlock::text(format!(
        "Cantor coordination {operation} returned {status}; use structuredContent as the complete machine response."
    ))];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(value);
    result
}

fn operation_hint(value: &Value) -> CoordinationToolOperation {
    match value
        .get("request")
        .and_then(|request| request.get("operation"))
        .and_then(Value::as_str)
    {
        Some("begin") => CoordinationToolOperation::Begin,
        Some("advance") => CoordinationToolOperation::Advance,
        _ => CoordinationToolOperation::Unavailable,
    }
}

fn bounded(message: &str) -> String {
    message.chars().take(512).collect()
}

fn schema_object<T: JsonSchema>() -> JsonObject {
    serde_json::to_value(schemars::schema_for!(T))
        .expect("generated schema must serialize")
        .as_object()
        .expect("generated schema root must be an object")
        .clone()
}

fn input_schema() -> JsonObject {
    schema_object::<StepProcedureCoordinationArguments>()
}

fn output_schema() -> JsonObject {
    schema_object::<CoordinationToolResponse>()
}
