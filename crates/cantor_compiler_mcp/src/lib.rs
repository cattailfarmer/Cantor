//! Stateless MCP transport for Cantor's native lifecycle validator.
//!
//! The adapter owns no lifecycle state and delegates semantic judgment to the
//! closed `cantor_core` protocol. It does not author, repair, sign, execute,
//! admit, install, deploy, or recognize an artifact.

use std::sync::Arc;

use cantor_core::{
    NATIVE_LIFECYCLE_MAX_INPUT_BYTES, NATIVE_LIFECYCLE_VALIDATION_PROTOCOL,
    NativeLifecycleValidationFaultKind, NativeLifecycleValidationOutcome,
    NativeLifecycleValidationRequest, NativeLifecycleValidationResponse,
    validate_native_lifecycle_request,
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

pub const TOOL_NAME: &str = "validate_native_lifecycle";
pub const ADAPTER_PROFILE: &str = "cantor-native-lifecycle-validation-mcp/0.1";
pub const MAX_ARGUMENT_BYTES: usize = NATIVE_LIFECYCLE_MAX_INPUT_BYTES + 65_536;
pub const SERVER_INSTRUCTIONS: &str = "Use validate_native_lifecycle between inference passes only when you have one complete exact Cantor native lifecycle request. Preserve structuredContent as the authoritative machine response. A valid response means the supplied representation coheres under caller-supplied public trust context; it does not establish physical truth, correctness, safety, verification passage, permission, global single-use consumption, signing, admission, installation, deployment, execution, or successor authority. This server stores no lifecycle state, invokes no model, and performs no external effect.";

#[derive(Clone, Debug, Default)]
pub struct CompilerMcpServer;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateNativeLifecycleArguments {
    pub request: NativeLifecycleValidationRequest,
}

impl CompilerMcpServer {
    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Replay one complete caller-supplied Cantor native artifact or verification lifecycle. Returns exact stage, identity, disposition, and fault accounting; performs no build or other external effect.",
            input_schema(),
        )
        .with_title("Validate Cantor native lifecycle")
        .with_raw_output_schema(Arc::new(output_schema()))
        .with_annotations(
            ToolAnnotations::with_title("Validate Cantor native lifecycle")
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
                return response_result(NativeLifecycleValidationResponse::input_refused(
                    NativeLifecycleValidationFaultKind::Wire,
                    "mcp.arguments",
                    bounded(&error.to_string()),
                ));
            }
        };
        if encoded_length > MAX_ARGUMENT_BYTES {
            return response_result(NativeLifecycleValidationResponse::input_refused(
                NativeLifecycleValidationFaultKind::InvalidBound,
                "mcp.arguments",
                format!(
                    "tool arguments contain {encoded_length} bytes; maximum is {MAX_ARGUMENT_BYTES}"
                ),
            ));
        }
        let parsed: ValidateNativeLifecycleArguments = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return response_result(NativeLifecycleValidationResponse::input_refused(
                    NativeLifecycleValidationFaultKind::Wire,
                    "mcp.arguments",
                    bounded(&error.to_string()),
                ));
            }
        };
        response_result(validate_native_lifecycle_request(&parsed.request))
    }
}

impl ServerHandler for CompilerMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-compiler", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor native lifecycle validator")
                    .with_description(
                        "Stateless read-only native compiler lifecycle replay through one typed tool.",
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

fn response_result(response: NativeLifecycleValidationResponse) -> CallToolResult {
    let (value, is_error, summary) = match serde_json::to_value(&response) {
        Ok(value) => {
            let is_error = !matches!(
                response.outcome,
                NativeLifecycleValidationOutcome::ArtifactValid
                    | NativeLifecycleValidationOutcome::VerificationValid
            );
            (value, is_error, outcome_name(&response.outcome))
        }
        Err(error) => {
            let fallback = NativeLifecycleValidationResponse::input_refused(
                NativeLifecycleValidationFaultKind::Wire,
                "mcp.response",
                bounded(&error.to_string()),
            );
            let value = serde_json::to_value(fallback).unwrap_or_else(|_| {
                json!({
                    "protocol": NATIVE_LIFECYCLE_VALIDATION_PROTOCOL,
                    "request_id": null,
                    "operation": null,
                    "outcome": "input_refused",
                    "deepest_valid_stage": null,
                    "stage_account": [],
                    "artifact_id": null,
                    "artifact_digest": null,
                    "verification_disposition": null,
                    "faults": [],
                    "non_authority": "response serialization failed; no authority granted"
                })
            });
            (value, true, "input_refused")
        }
    };
    let content = vec![ContentBlock::text(format!(
        "Cantor native lifecycle returned {summary}; use structuredContent as the complete machine response."
    ))];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(value);
    result
}

fn outcome_name(outcome: &NativeLifecycleValidationOutcome) -> &'static str {
    match outcome {
        NativeLifecycleValidationOutcome::ArtifactValid => "artifact_valid",
        NativeLifecycleValidationOutcome::VerificationValid => "verification_valid",
        NativeLifecycleValidationOutcome::LifecycleRefused => "lifecycle_refused",
        NativeLifecycleValidationOutcome::InputRefused => "input_refused",
    }
}

fn bounded(message: &str) -> String {
    message.chars().take(512).collect()
}

fn input_schema() -> JsonObject {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ValidateNativeLifecycleArguments",
        "type": "object",
        "additionalProperties": false,
        "required": ["request"],
        "properties": {
            "request": {
                "type": "object",
                "description": "One complete strict cantor.native_lifecycle_validation.v1 request. Nested runtime decoding rejects unknown or incomplete forms."
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
        "title": "NativeLifecycleValidationResponse",
        "type": "object",
        "description": "Exact cantor.native_lifecycle_validation.v1 structured response; validity is coherence, not effect authority.",
        "additionalProperties": false,
        "required": ["protocol", "request_id", "operation", "outcome", "deepest_valid_stage", "stage_account", "artifact_id", "artifact_digest", "verification_disposition", "faults", "non_authority"],
        "properties": {
            "protocol": { "type": "string" },
            "request_id": { "type": ["string", "null"] },
            "operation": { "type": ["string", "null"] },
            "outcome": { "enum": ["artifact_valid", "verification_valid", "lifecycle_refused", "input_refused"] },
            "deepest_valid_stage": { "type": ["string", "null"] },
            "stage_account": { "type": "array", "items": { "type": "string" } },
            "artifact_id": { "type": ["string", "null"] },
            "artifact_digest": { "type": ["object", "null"] },
            "verification_disposition": { "type": ["string", "null"] },
            "faults": { "type": "array", "items": { "type": "object" } },
            "non_authority": { "type": "string" }
        }
    })
    .as_object()
    .expect("output schema root is an object")
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_mapping_keeps_valid_and_refused_status_distinct() {
        let valid = NativeLifecycleValidationResponse {
            protocol: cantor_core::NATIVE_LIFECYCLE_VALIDATION_PROTOCOL.to_owned(),
            request_id: None,
            operation: None,
            outcome: NativeLifecycleValidationOutcome::ArtifactValid,
            deepest_valid_stage: None,
            stage_account: Vec::new(),
            artifact_id: None,
            artifact_digest: None,
            verification_disposition: None,
            faults: Vec::new(),
            non_authority: cantor_core::NATIVE_LIFECYCLE_VALIDATION_NON_AUTHORITY.to_owned(),
        };
        assert_eq!(response_result(valid).is_error, Some(false));
        let refused = NativeLifecycleValidationResponse::input_refused(
            NativeLifecycleValidationFaultKind::Wire,
            "test",
            "refused",
        );
        assert_eq!(response_result(refused).is_error, Some(true));
    }
}
