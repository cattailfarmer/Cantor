//! Volatile MCP custody for complete native lifecycle validation requests.
//!
//! The adapter serializes access to one process-local immutable core registry.
//! It adds no persistence, authentication, model, runner, or external effect.

use std::sync::Arc;

use cantor_core::{
    ContentDigest, NATIVE_LIFECYCLE_MAX_INPUT_BYTES, NativeLifecycleCustodyHandle,
    NativeLifecycleCustodyRegistry, NativeLifecycleValidationOutcome,
    NativeLifecycleValidationRequest, NativeLifecycleValidationResponse,
    new_native_lifecycle_custody_registry, register_native_lifecycle_custody,
    validate_native_lifecycle_custody_registry, validate_native_lifecycle_from_custody,
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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

pub const TOOL_NAME: &str = "manage_native_lifecycle_custody";
pub const RESPONSE_PROFILE: &str = "cantor-native-lifecycle-volatile-custody-mcp/0.1";
pub const MAX_ARGUMENT_BYTES: usize = NATIVE_LIFECYCLE_MAX_INPUT_BYTES + 65_536;
pub const SERVER_INSTRUCTIONS: &str = "REGISTER sends one complete exact lifecycle request once and returns a compact handle. VALIDATE replays retained meaning by that exact handle. INSPECT returns bounded registry metadata and never request bodies. Preserve structuredContent and every digest. State is volatile: restart loses all entries. A digest is a locator commitment, not reconstruction, authentication, authorization, truth, safety, permission, or effect authority. This server invokes no model and performs no filesystem, process, network, signing, installation, deployment, or execution operation.";
pub const RESPONSE_NONCLAIMS: [&str; 6] = [
    "state is process-local and restart loses every retained request",
    "digest lookup returns retained meaning and does not reconstruct omitted meaning",
    "custody coherence is not truth correctness safety or verification passage",
    "digests are not authentication authorization signatures or permissions",
    "no client isolation persistence expiry eviction or crash recovery is claimed",
    "no provider model filesystem process network runner or external effect is accessed",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyOperation {
    Register,
    Validate,
    Inspect,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyStatus {
    Registered,
    Validated,
    Inspected,
    Refused,
    InvalidRequest,
    InternalFault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CustodyCommand {
    Register {
        request: Box<NativeLifecycleValidationRequest>,
    },
    Validate {
        handle: NativeLifecycleCustodyHandle,
    },
    Inspect,
}

impl CustodyCommand {
    const fn operation(&self) -> CustodyOperation {
        match self {
            Self::Register { .. } => CustodyOperation::Register,
            Self::Validate { .. } => CustodyOperation::Validate,
            Self::Inspect => CustodyOperation::Inspect,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyArguments {
    pub command: CustodyCommand,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyRegistrySummary {
    pub profile: String,
    pub entry_count: usize,
    pub retained_request_bytes: u64,
    pub root_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyFault {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyResponse {
    pub profile: String,
    pub operation: CustodyOperation,
    pub status: CustodyStatus,
    pub registry: Option<CustodyRegistrySummary>,
    pub handle: Option<NativeLifecycleCustodyHandle>,
    pub lifecycle_response: Option<NativeLifecycleValidationResponse>,
    pub fault: Option<CustodyFault>,
    pub nonclaims: Vec<String>,
}

impl CustodyResponse {
    #[must_use]
    pub fn is_error(&self) -> bool {
        match self.status {
            CustodyStatus::Refused
            | CustodyStatus::InvalidRequest
            | CustodyStatus::InternalFault => true,
            CustodyStatus::Validated => self.lifecycle_response.as_ref().is_none_or(|response| {
                matches!(
                    response.outcome,
                    NativeLifecycleValidationOutcome::LifecycleRefused
                        | NativeLifecycleValidationOutcome::InputRefused
                )
            }),
            CustodyStatus::Registered | CustodyStatus::Inspected => false,
        }
    }

    fn success(
        operation: CustodyOperation,
        status: CustodyStatus,
        registry: CustodyRegistrySummary,
        handle: Option<NativeLifecycleCustodyHandle>,
        lifecycle_response: Option<NativeLifecycleValidationResponse>,
    ) -> Self {
        Self {
            profile: RESPONSE_PROFILE.to_owned(),
            operation,
            status,
            registry: Some(registry),
            handle,
            lifecycle_response,
            fault: None,
            nonclaims: nonclaims(),
        }
    }

    fn failed(
        operation: CustodyOperation,
        status: CustodyStatus,
        registry: Option<CustodyRegistrySummary>,
        code: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self {
            profile: RESPONSE_PROFILE.to_owned(),
            operation,
            status,
            registry,
            handle: None,
            lifecycle_response: None,
            fault: Some(CustodyFault {
                code: code.into(),
                message: bounded(message.as_ref()),
            }),
            nonclaims: nonclaims(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompilerCustodyMcpServer {
    registry: Arc<Mutex<NativeLifecycleCustodyRegistry>>,
}

impl CompilerCustodyMcpServer {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            registry: Arc::new(Mutex::new(new_native_lifecycle_custody_registry()?)),
        })
    }

    pub async fn snapshot(&self) -> NativeLifecycleCustodyRegistry {
        self.registry.lock().await.clone()
    }

    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Register one complete native lifecycle request, validate a retained request by compact handle, or inspect bounded volatile registry metadata. Retained request bodies are never returned.",
            input_schema(),
        )
        .with_title("Manage Cantor native lifecycle custody")
        .with_raw_output_schema(Arc::new(output_schema()))
        .with_annotations(
            ToolAnnotations::with_title("Manage Cantor native lifecycle custody")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        )
    }

    pub async fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let value = Value::Object(arguments.unwrap_or_default());
        let operation = operation_hint(&value);
        let encoded_length = match serde_json::to_vec(&value) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                return self
                    .failure(
                        operation,
                        CustodyStatus::InternalFault,
                        "argument_encoding_failed",
                        error.to_string(),
                    )
                    .await;
            }
        };
        if encoded_length > MAX_ARGUMENT_BYTES {
            return self
                .failure(
                    operation,
                    CustodyStatus::InvalidRequest,
                    "argument_limit_exceeded",
                    format!(
                        "tool arguments contain {encoded_length} bytes; maximum is {MAX_ARGUMENT_BYTES}"
                    ),
                )
                .await;
        }
        if let Err(error) = validate_command_shape(&value) {
            return self
                .failure(
                    operation,
                    CustodyStatus::InvalidRequest,
                    "invalid_command_shape",
                    error,
                )
                .await;
        }
        let parsed: CustodyArguments = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return self
                    .failure(
                        operation,
                        CustodyStatus::InvalidRequest,
                        "invalid_arguments",
                        error.to_string(),
                    )
                    .await;
            }
        };
        let mut registry = self.registry.lock().await;
        response_result(apply_command(&mut registry, parsed.command))
    }

    async fn failure(
        &self,
        operation: CustodyOperation,
        status: CustodyStatus,
        code: &str,
        message: String,
    ) -> CallToolResult {
        let registry = self.registry.lock().await;
        let summary = registry_summary(&registry).ok();
        response_result(CustodyResponse::failed(
            operation, status, summary, code, message,
        ))
    }
}

fn apply_command(
    registry: &mut NativeLifecycleCustodyRegistry,
    command: CustodyCommand,
) -> CustodyResponse {
    let operation = command.operation();
    let summary = match registry_summary(registry) {
        Ok(summary) => summary,
        Err(error) => {
            return CustodyResponse::failed(
                operation,
                CustodyStatus::InternalFault,
                None,
                "invalid_registry",
                error,
            );
        }
    };
    match command {
        CustodyCommand::Register { request } => {
            match register_native_lifecycle_custody(registry, &request) {
                Ok((successor, handle)) => {
                    let successor_summary = match registry_summary(&successor) {
                        Ok(summary) => summary,
                        Err(error) => {
                            return CustodyResponse::failed(
                                operation,
                                CustodyStatus::InternalFault,
                                Some(summary),
                                "invalid_successor",
                                error,
                            );
                        }
                    };
                    *registry = successor;
                    CustodyResponse::success(
                        operation,
                        CustodyStatus::Registered,
                        successor_summary,
                        Some(handle),
                        None,
                    )
                }
                Err(error) => CustodyResponse::failed(
                    operation,
                    CustodyStatus::Refused,
                    Some(summary),
                    "registration_refused",
                    error,
                ),
            }
        }
        CustodyCommand::Validate { handle } => {
            match validate_native_lifecycle_from_custody(registry, &handle) {
                Ok(response) => CustodyResponse::success(
                    operation,
                    CustodyStatus::Validated,
                    summary,
                    Some(handle),
                    Some(response),
                ),
                Err(error) => CustodyResponse::failed(
                    operation,
                    CustodyStatus::Refused,
                    Some(summary),
                    "handle_refused",
                    error,
                ),
            }
        }
        CustodyCommand::Inspect => {
            CustodyResponse::success(operation, CustodyStatus::Inspected, summary, None, None)
        }
    }
}

fn registry_summary(
    registry: &NativeLifecycleCustodyRegistry,
) -> Result<CustodyRegistrySummary, String> {
    validate_native_lifecycle_custody_registry(registry)?;
    Ok(CustodyRegistrySummary {
        profile: registry.profile.clone(),
        entry_count: registry.entry_count,
        retained_request_bytes: registry.retained_request_bytes,
        root_digest: registry.root_digest.clone(),
    })
}

impl ServerHandler for CompilerCustodyMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-compiler-custody", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor volatile native lifecycle custody")
                    .with_description("Process-local content-addressed lifecycle request custody."),
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

fn response_result(response: CustodyResponse) -> CallToolResult {
    let is_error = response.is_error();
    let operation = operation_name(response.operation);
    let status = status_name(response.status);
    let value = serde_json::to_value(&response).unwrap_or_else(|_| {
        json!({
            "profile": RESPONSE_PROFILE,
            "operation": "unavailable",
            "status": "internal_fault",
            "registry": null,
            "handle": null,
            "lifecycle_response": null,
            "fault": {"code": "response_encoding_failed", "message": "response serialization failed"},
            "nonclaims": RESPONSE_NONCLAIMS
        })
    });
    let content = vec![ContentBlock::text(format!(
        "Cantor lifecycle custody {operation} returned {status}; use structuredContent for the complete machine response."
    ))];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(value);
    result
}

fn operation_hint(value: &Value) -> CustodyOperation {
    match value.pointer("/command/operation").and_then(Value::as_str) {
        Some("register") => CustodyOperation::Register,
        Some("validate") => CustodyOperation::Validate,
        Some("inspect") => CustodyOperation::Inspect,
        _ => CustodyOperation::Unavailable,
    }
}

fn validate_command_shape(value: &Value) -> Result<(), String> {
    let root = value
        .as_object()
        .ok_or_else(|| "tool arguments must be an object".to_owned())?;
    if root.len() != 1 || !root.contains_key("command") {
        return Err("tool arguments must contain exactly command".to_owned());
    }
    let command = root["command"]
        .as_object()
        .ok_or_else(|| "command must be an object".to_owned())?;
    let allowed = match command.get("operation").and_then(Value::as_str) {
        Some("register") => &["operation", "request"][..],
        Some("validate") => &["operation", "handle"][..],
        Some("inspect") => &["operation"][..],
        _ => return Err("command operation is not recognized".to_owned()),
    };
    if command.len() != allowed.len() || command.keys().any(|key| !allowed.contains(&key.as_str()))
    {
        return Err("command contains missing or unknown fields".to_owned());
    }
    Ok(())
}

const fn operation_name(operation: CustodyOperation) -> &'static str {
    match operation {
        CustodyOperation::Register => "register",
        CustodyOperation::Validate => "validate",
        CustodyOperation::Inspect => "inspect",
        CustodyOperation::Unavailable => "unavailable",
    }
}

const fn status_name(status: CustodyStatus) -> &'static str {
    match status {
        CustodyStatus::Registered => "registered",
        CustodyStatus::Validated => "validated",
        CustodyStatus::Inspected => "inspected",
        CustodyStatus::Refused => "refused",
        CustodyStatus::InvalidRequest => "invalid_request",
        CustodyStatus::InternalFault => "internal_fault",
    }
}

fn nonclaims() -> Vec<String> {
    RESPONSE_NONCLAIMS.iter().map(ToString::to_string).collect()
}

fn bounded(message: &str) -> String {
    message.chars().take(512).collect()
}

fn input_schema() -> JsonObject {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "NativeLifecycleCustodyArguments",
        "type": "object",
        "additionalProperties": false,
        "required": ["command"],
        "properties": {
            "command": {
                "type": "object",
                "description": "Strict tagged register, validate, or inspect command. Runtime decoding closes each nested Cantor form."
            }
        }
    })
    .as_object()
    .expect("input schema root is an object")
    .clone()
}

fn output_schema() -> JsonObject {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "NativeLifecycleCustodyResponse",
        "type": "object",
        "additionalProperties": false,
        "required": ["profile", "operation", "status", "registry", "handle", "lifecycle_response", "fault", "nonclaims"],
        "properties": {
            "profile": {"type": "string"},
            "operation": {"enum": ["register", "validate", "inspect", "unavailable"]},
            "status": {"enum": ["registered", "validated", "inspected", "refused", "invalid_request", "internal_fault"]},
            "registry": {"type": ["object", "null"]},
            "handle": {"type": ["object", "null"]},
            "lifecycle_response": {"type": ["object", "null"]},
            "fault": {"type": ["object", "null"]},
            "nonclaims": {"type": "array", "items": {"type": "string"}}
        }
    })
    .as_object()
    .expect("output schema root is an object")
    .clone()
}
