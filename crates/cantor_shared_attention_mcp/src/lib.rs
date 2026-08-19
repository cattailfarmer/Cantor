//! Stateless MCP transport for Cantor's pure shared-attention tool contract.
//!
//! The adapter carries complete typed state through one tool call. It does not
//! retain frames, invoke models, open a network listener, or create semantic
//! authority beyond `cantor_core`.

#![recursion_limit = "512"]

use std::sync::Arc;

use cantor_core::{
    SharedAttentionToolRequest, SharedAttentionToolResponse, execute_shared_attention_tool_request,
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

pub const TOOL_NAME: &str = "coordinate_attention";
pub const ADAPTER_PROFILE: &str = "cantor-shared-attention-mcp/0.1";
pub const MAX_ARGUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const SERVER_INSTRUCTIONS: &str = "Use coordinate_attention only between inference passes with a complete exact request. Preserve generation, frame and dream digests, policy, epistemic labels, backpressure, faults, and nonclaims. Never invent bindings. A sealed frame is coordinated, not externally proven true; a DreamFrame is hypothetical. This server stores no frame, invokes no model, shares no hidden state, and authorizes no effect.";

#[derive(Clone, Debug, Default)]
pub struct SharedAttentionMcpServer;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoordinateAttentionArguments {
    pub request: SharedAttentionToolRequest,
}

impl SharedAttentionMcpServer {
    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Apply one pure Cantor shared-attention validation or transition to complete caller-supplied state. Returns an exact typed successor, backpressure receipt, or refusal. Call between model passes; this tool stores no state and grants no effect authority.",
            input_schema(),
        )
        .with_title("Coordinate shared attention")
        .with_raw_output_schema(Arc::new(output_schema()))
        .with_annotations(
            ToolAnnotations::with_title("Coordinate shared attention")
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
    }

    pub fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let value = Value::Object(arguments.unwrap_or_default());
        let encoded_length = match serde_json::to_vec(&value) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                return response_result(SharedAttentionToolResponse::invalid_request(
                    "invalid_arguments",
                    bounded(&error.to_string()),
                ));
            }
        };
        if encoded_length > MAX_ARGUMENT_BYTES {
            return response_result(SharedAttentionToolResponse::invalid_request(
                "argument_limit_exceeded",
                format!(
                    "tool arguments contain {encoded_length} bytes; maximum is {MAX_ARGUMENT_BYTES}"
                ),
            ));
        }
        let parsed: CoordinateAttentionArguments = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return response_result(SharedAttentionToolResponse::invalid_request(
                    "invalid_arguments",
                    bounded(&error.to_string()),
                ));
            }
        };
        response_result(execute_shared_attention_tool_request(parsed.request))
    }
}

impl ServerHandler for SharedAttentionMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-shared-attention", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor shared-attention coprocessor")
                    .with_description(
                        "Stateless typed semantic-frame coordination through one pure tool.",
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

fn response_result(response: SharedAttentionToolResponse) -> CallToolResult {
    let (value, is_error) = match serde_json::to_value(&response) {
        Ok(value) => (value, response.is_error()),
        Err(error) => {
            let fallback = SharedAttentionToolResponse::internal_fault(
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
                            "message": "shared-attention response serialization failed",
                            "subject_refs": []
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
        "Cantor shared-attention {operation} returned {status}; use structuredContent as the complete machine response."
    ))];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(value);
    result
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
    schema_object::<CoordinateAttentionArguments>()
}

fn output_schema() -> JsonObject {
    schema_object::<SharedAttentionToolResponse>()
}
