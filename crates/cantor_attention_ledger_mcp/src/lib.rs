//! Volatile process-local MCP custody for the pure attention reentry ledger.

#![recursion_limit = "512"]

use std::sync::Arc;

use cantor_core::{
    AttentionLedger, AttentionLedgerCommand, AttentionLedgerResponse, SemanticId,
    SharedAttentionToolFault, execute_attention_ledger_command, new_attention_ledger,
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
use tokio::sync::Mutex;

pub const TOOL_NAME: &str = "continue_attention_session";
pub const ADAPTER_PROFILE: &str = "cantor-attention-reentry-ledger-mcp/0.1";
pub const MAX_ARGUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const SERVER_INSTRUCTIONS: &str = "Use continue_attention_session to open, apply, inspect, or read one exact local attention trajectory. Every command must carry the current ledger digest; apply must also carry the exact session sequence and head digest. Preserve continuations, events, core responses, faults, and epistemic labels. This process is volatile: restart loses all unpersisted sessions. It invokes no model, opens no network listener, signs no meaning, and authorizes no effect.";

#[derive(Clone, Debug)]
pub struct AttentionLedgerMcpServer {
    ledger: Arc<Mutex<AttentionLedger>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContinueAttentionArguments {
    pub request: AttentionLedgerCommand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LedgerMcpStatus {
    Succeeded,
    Refused,
    InvalidRequest,
    InternalFault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionLedgerMcpResponse {
    pub profile: String,
    pub status: LedgerMcpStatus,
    pub result: Option<AttentionLedgerResponse>,
    pub fault: Option<SharedAttentionToolFault>,
    pub nonclaims: Vec<String>,
}

impl AttentionLedgerMcpResponse {
    fn success(result: AttentionLedgerResponse) -> Self {
        Self::new(LedgerMcpStatus::Succeeded, Some(result), None)
    }

    fn fault(status: LedgerMcpStatus, code: &str, message: impl Into<String>) -> Self {
        Self::new(
            status,
            None,
            Some(SharedAttentionToolFault {
                code: code.to_owned(),
                message: message.into(),
                subject_refs: Default::default(),
            }),
        )
    }

    fn new(
        status: LedgerMcpStatus,
        result: Option<AttentionLedgerResponse>,
        fault: Option<SharedAttentionToolFault>,
    ) -> Self {
        Self {
            profile: ADAPTER_PROFILE.to_owned(),
            status,
            result,
            fault,
            nonclaims: vec![
                "process restart loses every unpersisted attention session".to_owned(),
                "ledger custody does not sign meaning or prove external truth".to_owned(),
                "no model hidden state or external effect is accessed".to_owned(),
            ],
        }
    }

    const fn is_error(&self) -> bool {
        !matches!(self.status, LedgerMcpStatus::Succeeded)
    }
}

impl AttentionLedgerMcpServer {
    pub fn new(ledger_id: SemanticId) -> Result<Self, cantor_core::SharedAttentionFault> {
        Ok(Self {
            ledger: Arc::new(Mutex::new(new_attention_ledger(ledger_id)?)),
        })
    }

    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Open or continue one content-addressed local Cantor attention session. Later apply calls omit the full base frame but must compare-and-set the exact ledger, sequence, and head digest. State is volatile and inspectable; no model or effect is invoked.",
            schema_object::<ContinueAttentionArguments>(),
        )
        .with_title("Continue attention session")
        .with_raw_output_schema(Arc::new(schema_object::<AttentionLedgerMcpResponse>()))
        .with_annotations(
            ToolAnnotations::with_title("Continue attention session")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        )
    }

    pub async fn snapshot(&self) -> AttentionLedger {
        self.ledger.lock().await.clone()
    }

    pub async fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let value = Value::Object(arguments.unwrap_or_default());
        let encoded_length = match serde_json::to_vec(&value) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                return response_result(AttentionLedgerMcpResponse::fault(
                    LedgerMcpStatus::InvalidRequest,
                    "invalid_arguments",
                    bounded(&error.to_string()),
                ));
            }
        };
        if encoded_length > MAX_ARGUMENT_BYTES {
            return response_result(AttentionLedgerMcpResponse::fault(
                LedgerMcpStatus::InvalidRequest,
                "argument_limit_exceeded",
                format!(
                    "tool arguments contain {encoded_length} bytes; maximum is {MAX_ARGUMENT_BYTES}"
                ),
            ));
        }
        let parsed: ContinueAttentionArguments = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return response_result(AttentionLedgerMcpResponse::fault(
                    LedgerMcpStatus::InvalidRequest,
                    "invalid_arguments",
                    bounded(&error.to_string()),
                ));
            }
        };

        let mut ledger = self.ledger.lock().await;
        match execute_attention_ledger_command(&ledger, parsed.request) {
            Ok(transition) => {
                if let Some(successor) = transition.successor {
                    *ledger = successor;
                }
                response_result(AttentionLedgerMcpResponse::success(transition.response))
            }
            Err(fault_value) => response_result(AttentionLedgerMcpResponse::new(
                LedgerMcpStatus::Refused,
                None,
                Some(fault_value.into()),
            )),
        }
    }
}

impl ServerHandler for AttentionLedgerMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-attention-ledger", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor attention reentry ledger")
                    .with_description(
                        "Volatile content-addressed local attention-session custody.",
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
        Ok(self.execute_tool_arguments(request.arguments).await.into())
    }
}

fn response_result(response: AttentionLedgerMcpResponse) -> CallToolResult {
    let (value, is_error) = match serde_json::to_value(&response) {
        Ok(value) => (value, response.is_error()),
        Err(error) => (
            json!({
                "profile": ADAPTER_PROFILE,
                "status": "internal_fault",
                "result": null,
                "fault": {
                    "code": "response_encoding_failed",
                    "message": bounded(&error.to_string()),
                    "subject_refs": []
                },
                "nonclaims": []
            }),
            true,
        ),
    };
    let status = value["status"].as_str().unwrap_or("internal_fault");
    let content = vec![ContentBlock::text(format!(
        "Cantor attention ledger returned {status}; use structuredContent as the complete result."
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
        .expect("generated schema serializes")
        .as_object()
        .expect("generated schema root is an object")
        .clone()
}
