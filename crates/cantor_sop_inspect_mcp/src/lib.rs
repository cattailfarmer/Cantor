//! Bounded official-MCP inspection of caller-supplied SOP bytes.
//!
//! This ephemeral adapter adds inherited-stream transport bookkeeping, not
//! filesystem-path, provider, model, service-installation or custody authority.
//! The original semantic wire bytes are retained exactly inside structuredContent.

mod transport;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use cantor_sop_inspect_wire::{Status, parse_request, parse_response, respond};
use cantor_sop_semantics::digest;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestMethod, CallToolRequestParams, CallToolResponse, CallToolResult,
        ContentBlock, Implementation, JsonObject, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
    },
    service::{RequestContext, RoleServer},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use transport::{SessionFault, SessionReport, run_io};

pub const TOOL_NAME: &str = "inspect_sop_semantics";
pub const REPLY_PROFILE: &str = "cantor-sop-inspection-mcp-reply/0.1";
pub const MAX_REQUEST_BYTES: usize = 262_144;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_INPUT_FRAME_BYTES: usize = 2_097_152;
pub const MAX_OUTPUT_FRAME_BYTES: usize = 4_194_304;
pub const MAX_INPUT_BYTES: usize = 8_388_608;
pub const MAX_RESERVED_OUTPUT_BYTES: usize = 8_388_608;
pub const MAX_MESSAGES: usize = 32;
pub const SESSION_SECONDS: u64 = 60;
pub const SHUTDOWN_MILLISECONDS: u64 = 250;
pub const PUBLIC_HOST_FAULT: &[u8] = b"cantor_semantic_inspection_mcp_refused\n";
pub const NON_AUTHORITY: &str = "Read-only caller-supplied semantic inspection through bounded ephemeral inherited-stream MCP transport only. No pathname acquisition, durable custody, provider, model, network listener, arbitrary process, shell, installed service, update, remote host, message, application mutation, operator approval, executable trust or semantic truth is established.";
pub const SERVER_INSTRUCTIONS: &str = "Call inspect_sop_semantics with exactly one wire_request_json string. Retain structuredContent and its exact nested wire_response_json bytes. This ephemeral P0 session has 32-message and 60-second ceilings including initialization. Await each response before closing input. The application owns trusted launch, restart and acceptance. No provider or autonomous agent work is performed.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    InspectionSucceeded,
    SemanticRefused,
    AdapterRefused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterFault {
    Arguments,
    RequestLimit,
    WireInput,
    ResponseLimit,
    ResponseShape,
    Busy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterReply {
    pub profile: String,
    pub outcome: Outcome,
    pub request_bytes: Option<usize>,
    pub request_sha256: Option<String>,
    pub response_bytes: Option<usize>,
    pub response_sha256: Option<String>,
    pub wire_response_json: Option<String>,
    pub fault_code: Option<AdapterFault>,
    pub non_authority: String,
}

impl AdapterReply {
    fn refused(fault: AdapterFault, input: Option<&str>) -> Self {
        Self {
            profile: REPLY_PROFILE.to_owned(),
            outcome: Outcome::AdapterRefused,
            request_bytes: input.map(str::len),
            // Never hash an unadmitted arbitrarily large direct-call argument.
            request_sha256: input
                .filter(|x| x.len() <= MAX_REQUEST_BYTES)
                .map(|x| digest::bytes(x.as_bytes())),
            response_bytes: None,
            response_sha256: None,
            wire_response_json: None,
            fault_code: Some(fault),
            non_authority: NON_AUTHORITY.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct InspectionMcpServer {
    active: Arc<AtomicBool>,
}

struct ActiveGuard<'a>(&'a AtomicBool);
impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl InspectionMcpServer {
    pub fn tool_definition() -> Tool {
        let schema = json!({
            "type": "object", "additionalProperties": false,
            "required": ["wire_request_json"],
            "properties": {"wire_request_json": {"type": "string",
                "description": "Original strict SOP inspection wire JSON, at most262144 UTF-8 bytes."}}
        });
        Tool::new(
            TOOL_NAME,
            "Inspect supplied SOP semantics without ambient pathname or provider access.",
            schema.as_object().expect("fixed object schema").clone(),
        )
        .with_annotations(
            ToolAnnotations::with_title("Inspect supplied SOP semantics")
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
    }

    /// SDK-normalized argument map, not an original MCP envelope or a receipt.
    pub fn inspect_arguments(&self, arguments: Option<JsonObject>) -> AdapterReply {
        let Some(mut arguments) = arguments else {
            return AdapterReply::refused(AdapterFault::Arguments, None);
        };
        if arguments.len() != 1 {
            return AdapterReply::refused(AdapterFault::Arguments, None);
        }
        let Some(Value::String(input)) = arguments.remove("wire_request_json") else {
            return AdapterReply::refused(AdapterFault::Arguments, None);
        };
        if input.len() > MAX_REQUEST_BYTES {
            return AdapterReply::refused(AdapterFault::RequestLimit, Some(&input));
        }
        if self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return AdapterReply::refused(AdapterFault::Busy, Some(&input));
        }
        let _guard = ActiveGuard(&self.active);
        if parse_request(input.as_bytes()).is_err() {
            return AdapterReply::refused(AdapterFault::WireInput, Some(&input));
        }
        let Ok(output) = respond(input.as_bytes()) else {
            return AdapterReply::refused(AdapterFault::ResponseShape, Some(&input));
        };
        reply_from_output(&input, output)
    }

    pub fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        tool_result(self.inspect_arguments(arguments))
    }
}

fn reply_from_output(input: &str, output: Vec<u8>) -> AdapterReply {
    if output.len() > MAX_RESPONSE_BYTES {
        return AdapterReply::refused(AdapterFault::ResponseLimit, Some(input));
    }
    let Ok(response) = parse_response(&output) else {
        return AdapterReply::refused(AdapterFault::ResponseShape, Some(input));
    };
    let output_hash = digest::bytes(&output);
    let Ok(output) = String::from_utf8(output) else {
        return AdapterReply::refused(AdapterFault::ResponseShape, Some(input));
    };
    AdapterReply {
        profile: REPLY_PROFILE.to_owned(),
        outcome: match response.status {
            Status::Succeeded => Outcome::InspectionSucceeded,
            Status::Refused => Outcome::SemanticRefused,
        },
        request_bytes: Some(input.len()),
        request_sha256: Some(digest::bytes(input.as_bytes())),
        response_bytes: Some(output.len()),
        response_sha256: Some(output_hash),
        wire_response_json: Some(output),
        fault_code: None,
        non_authority: NON_AUTHORITY.to_owned(),
    }
}

fn tool_result(reply: AdapterReply) -> CallToolResult {
    let content = vec![ContentBlock::text(
        "Use structuredContent for the exact bounded inspection reply; no effect authority is granted.",
    )];
    let mut result = if reply.outcome == Outcome::InspectionSucceeded {
        CallToolResult::success(content)
    } else {
        CallToolResult::error(content)
    };
    result.structured_content =
        Some(serde_json::to_value(reply).expect("fixed serializable reply"));
    result
}

impl ServerHandler for InspectionMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "cantor-sop-inspect",
                env!("CARGO_PKG_VERSION"),
            ))
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_call_refuses_then_recovers() {
        let server = InspectionMcpServer::default();
        server.active.store(true, Ordering::Release);
        let args = || {
            json!({"wire_request_json": "{}"})
                .as_object()
                .unwrap()
                .clone()
        };
        assert_eq!(
            server.inspect_arguments(Some(args())).fault_code,
            Some(AdapterFault::Busy)
        );
        server.active.store(false, Ordering::Release);
        assert_eq!(
            server.inspect_arguments(Some(args())).fault_code,
            Some(AdapterFault::WireInput)
        );
        assert!(!server.active.load(Ordering::Acquire));
    }
    #[test]
    fn raw_output_limit_and_shape_refuse_without_echo() {
        assert_eq!(
            reply_from_output("{}", vec![b'x'; MAX_RESPONSE_BYTES + 1]).fault_code,
            Some(AdapterFault::ResponseLimit)
        );
        assert_eq!(
            reply_from_output("{}", vec![b'x'; MAX_RESPONSE_BYTES]).fault_code,
            Some(AdapterFault::ResponseShape)
        );
    }
}
