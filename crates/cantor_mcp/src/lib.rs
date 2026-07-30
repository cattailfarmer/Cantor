//! Read-only MCP projection of Cantor's deterministic protocol.
//!
//! This crate is intentionally an adapter, not another semantic authority.
//! It exposes one tool and delegates every valid request to `cantor_core`.

#![recursion_limit = "512"]

use std::{fmt, fs::File, io::Read, path::Path, sync::Arc};

use cantor_core::{
    EmbeddedRuntimeEnvironment, PreparedRuntime, ProtocolRequest, ProtocolResponse, ProtocolStatus,
    preflight_runtime_environment,
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
use serde::Deserialize;
use serde_json::{Value, json};

pub const TOOL_NAME: &str = "query_sop";
pub const ADAPTER_PROTOCOL_VERSION: &str = "cantor-mcp-adapter/0.1";
pub const MAX_ARGUMENT_BYTES: usize = 1_048_576;
pub const MAX_ENVIRONMENT_BYTES: usize = 67_108_864;

#[derive(Clone, Debug)]
pub struct CantorMcpServer {
    runtime: Arc<PreparedRuntime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartupFault {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for StartupFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for StartupFault {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuerySopArguments {
    request: ProtocolRequest,
}

impl CantorMcpServer {
    pub fn new(environment: EmbeddedRuntimeEnvironment) -> Result<Self, StartupFault> {
        preflight_environment(&environment)?;
        let runtime = PreparedRuntime::new(environment).map_err(|fault| StartupFault {
            code: "prepared_runtime_initialization_failed",
            message: bounded_message(&fault.to_string()),
        })?;
        Ok(Self {
            runtime: Arc::new(runtime),
        })
    }

    pub fn environment(&self) -> &EmbeddedRuntimeEnvironment {
        self.runtime.environment()
    }

    pub fn runtime(&self) -> &PreparedRuntime {
        &self.runtime
    }

    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Resolve or inspect signed SOP semantics through Cantor's deterministic, read-only protocol. Supply one complete supervisor-issued ProtocolRequest whose environment digest, package set, scope, caller context, and operation are explicit. Do not invent these bindings.",
            input_schema(),
        )
        .with_title("Query signed SOP")
        .with_raw_output_schema(Arc::new(output_schema()))
        .with_annotations(
            ToolAnnotations::with_title("Query signed SOP")
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
    }

    /// Executes the adapter operation without an MCP transport. This is the
    /// shared seam used by the live handler and equivalence tests.
    pub fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let argument_value = Value::Object(arguments.unwrap_or_default());
        let encoded_length = match serde_json::to_vec(&argument_value) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                return adapter_fault("invalid_arguments", bounded_message(&error.to_string()));
            }
        };
        if encoded_length > MAX_ARGUMENT_BYTES {
            return adapter_fault(
                "argument_limit_exceeded",
                format!(
                    "tool arguments contain {encoded_length} bytes; maximum is {MAX_ARGUMENT_BYTES}"
                ),
            );
        }
        let parsed: QuerySopArguments = match serde_json::from_value(argument_value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return adapter_fault("invalid_arguments", bounded_message(&error.to_string()));
            }
        };
        let response = self.runtime.execute(parsed.request);
        protocol_result(response)
    }
}

impl ServerHandler for CantorMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor signed semantic coprocessor")
                    .with_description(
                        "Read-only access to a pinned, signed SOP environment through one deterministic tool.",
                    ),
            )
            .with_instructions(
                "Use query_sop when the subject may be governed by the loaded signed SOP environment and a trusted supervisor has supplied a ProtocolRequest template. This server does not mint caller identity, package bindings, environment digest, or authority scope; do not guess them. Treat structuredContent as the authoritative ProtocolResponse. On a fault, preserve its exit_class, faults, proof, and continuation; do not invent missing authority.",
            )
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

pub fn load_environment_bytes(bytes: &[u8]) -> Result<EmbeddedRuntimeEnvironment, StartupFault> {
    if bytes.len() > MAX_ENVIRONMENT_BYTES {
        return Err(StartupFault {
            code: "environment_limit_exceeded",
            message: format!(
                "environment contains {} bytes; maximum is {MAX_ENVIRONMENT_BYTES}",
                bytes.len()
            ),
        });
    }
    serde_json::from_slice(bytes).map_err(|error| StartupFault {
        code: "invalid_environment",
        message: bounded_message(&error.to_string()),
    })
}

pub fn load_environment_file(path: &Path) -> Result<EmbeddedRuntimeEnvironment, StartupFault> {
    let file = File::open(path).map_err(|error| StartupFault {
        code: "environment_read_failed",
        message: bounded_message(&error.to_string()),
    })?;
    let length = file
        .metadata()
        .map_err(|error| StartupFault {
            code: "environment_metadata_failed",
            message: bounded_message(&error.to_string()),
        })?
        .len();
    if length > MAX_ENVIRONMENT_BYTES as u64 {
        return Err(StartupFault {
            code: "environment_limit_exceeded",
            message: format!(
                "environment contains {length} bytes; maximum is {MAX_ENVIRONMENT_BYTES}"
            ),
        });
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_ENVIRONMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| StartupFault {
            code: "environment_read_failed",
            message: bounded_message(&error.to_string()),
        })?;
    load_environment_bytes(&bytes)
}

fn preflight_environment(environment: &EmbeddedRuntimeEnvironment) -> Result<(), StartupFault> {
    preflight_runtime_environment(environment)
        .map(|_| ())
        .map_err(|fault| StartupFault {
            code: match fault.code.as_str() {
                "unsupported_environment_version" => "unsupported_environment_version",
                "empty_environment" => "empty_environment",
                "environment_digest_failed" => "environment_digest_failed",
                "environment_package_rejected" => "environment_package_rejected",
                "environment_fabric_rejected" => "environment_fabric_rejected",
                _ => "environment_preflight_failed",
            },
            message: bounded_message(&fault.message),
        })
}

fn protocol_result(response: ProtocolResponse) -> CallToolResult {
    let value = match serde_json::to_value(&response) {
        Ok(value) => value,
        Err(error) => {
            return adapter_fault(
                "response_encoding_failed",
                bounded_message(&error.to_string()),
            );
        }
    };
    let summary = format!(
        "Cantor {} {}; exit_class={}; continuation={}.",
        value["operation"].as_str().unwrap_or("operation"),
        value["status"].as_str().unwrap_or("fault"),
        value["exit_class"].as_str().unwrap_or("internal_fault"),
        value["continuation"].as_str().unwrap_or("stop")
    );
    structured_result(value, response.status != ProtocolStatus::Success, summary)
}

fn adapter_fault(code: &str, message: String) -> CallToolResult {
    structured_result(
        json!({
        "adapter_protocol_version": ADAPTER_PROTOCOL_VERSION,
        "status": "fault",
        "fault": {
            "code": code,
            "message": message
        }
        }),
        true,
        format!("Cantor MCP adapter fault: {code}."),
    )
}

fn structured_result(value: Value, is_error: bool, summary: String) -> CallToolResult {
    let content = vec![ContentBlock::text(summary)];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(value);
    result
}

fn bounded_message(message: &str) -> String {
    message.chars().take(512).collect()
}

fn object(value: Value) -> JsonObject {
    value
        .as_object()
        .expect("static schema must be a JSON object")
        .clone()
}

fn input_schema() -> JsonObject {
    object(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["request"],
        "properties": {
            "request": { "$ref": "#/$defs/protocol_request" }
        },
        "$defs": {
            "semantic_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 512,
                "pattern": "^[A-Za-z0-9_.:/-]+$"
            },
            "digest": {
                "type": "object",
                "additionalProperties": false,
                "required": ["algorithm", "value"],
                "properties": {
                    "algorithm": { "type": "string", "const": "SHA-256" },
                    "value": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                }
            },
            "string_set": {
                "type": "array",
                "items": { "type": "string" },
                "uniqueItems": true
            },
            "semantic_id_set": {
                "type": "array",
                "items": { "$ref": "#/$defs/semantic_id" },
                "uniqueItems": true
            },
            "unit_kind_set": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "Term", "Value", "Relation", "Declaration", "Judgment",
                        "Contract", "Operation", "Program", "Result", "Fault"
                    ]
                },
                "uniqueItems": true
            },
            "authority_scope": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "projects", "namespaces", "semantic_kinds", "perspectives",
                    "instruction_capabilities"
                ],
                "properties": {
                    "projects": { "$ref": "#/$defs/string_set" },
                    "namespaces": { "$ref": "#/$defs/string_set" },
                    "semantic_kinds": { "$ref": "#/$defs/unit_kind_set" },
                    "perspectives": { "$ref": "#/$defs/string_set" },
                    "instruction_capabilities": { "$ref": "#/$defs/string_set" }
                }
            },
            "caller_context": {
                "type": "object",
                "additionalProperties": false,
                "required": ["caller_id", "purpose", "effect_boundary"],
                "properties": {
                    "caller_id": { "$ref": "#/$defs/semantic_id" },
                    "purpose": { "type": "string" },
                    "job_id": {
                        "oneOf": [
                            { "$ref": "#/$defs/semantic_id" },
                            { "type": "null" }
                        ]
                    },
                    "effect_boundary": { "type": "string", "const": "read_only" }
                }
            },
            "expected_package": {
                "type": "object",
                "additionalProperties": false,
                "required": ["package_id", "package_digest"],
                "properties": {
                    "package_id": { "$ref": "#/$defs/semantic_id" },
                    "package_digest": { "$ref": "#/$defs/digest" }
                }
            },
            "authority_context": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "caller_id", "allowed_package_scopes", "operation",
                    "effect_boundary"
                ],
                "properties": {
                    "caller_id": { "$ref": "#/$defs/semantic_id" },
                    "allowed_package_scopes": { "$ref": "#/$defs/string_set" },
                    "operation": { "type": "string", "const": "semantic_read" },
                    "effect_boundary": { "type": "string", "const": "read_only" }
                }
            },
            "query_budget": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "maximum_records", "maximum_paths", "maximum_depth",
                    "maximum_bytes", "maximum_elapsed_milliseconds"
                ],
                "properties": {
                    "maximum_records": { "type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64 },
                    "maximum_paths": { "type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64 },
                    "maximum_depth": { "type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64 },
                    "maximum_bytes": { "type": "integer", "minimum": 0 },
                    "maximum_elapsed_milliseconds": { "type": "integer", "minimum": 0 }
                }
            },
            "query_request": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "protocol_version", "request_id", "term_set", "purpose",
                    "use_case_set", "include_boundary_set", "exclude_boundary_set",
                    "requested_detail_kinds", "search_modes", "relation_types",
                    "criteria", "source_scopes", "perspectives", "known_units",
                    "authority_context", "budget"
                ],
                "properties": {
                    "protocol_version": { "type": "string", "const": "cantor-query/0.1" },
                    "request_id": { "$ref": "#/$defs/semantic_id" },
                    "term_set": { "$ref": "#/$defs/string_set" },
                    "subject": { "type": ["string", "null"] },
                    "purpose": { "type": "string" },
                    "use_case_set": { "$ref": "#/$defs/string_set" },
                    "include_boundary_set": { "$ref": "#/$defs/string_set" },
                    "exclude_boundary_set": { "$ref": "#/$defs/string_set" },
                    "description_need": { "type": ["string", "null"] },
                    "requested_detail_kinds": {
                        "type": "array",
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": [
                                "Term", "Clause", "Definition", "Description", "UseCase",
                                "Boundary", "Condition", "Relation", "Instruction",
                                "Authority", "Evidence", "Fault", "SourceSpan", "Derivation"
                            ]
                        }
                    },
                    "search_modes": {
                        "type": "array",
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": ["Exact", "Contextual", "Relational", "Lexical", "Routed", "Composed"]
                        }
                    },
                    "relation_types": {
                        "type": "array",
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": [
                                "Alias", "Broader", "Narrower", "DependsOn",
                                "DistinctFrom", "Supports", "Contradicts"
                            ]
                        }
                    },
                    "criteria": { "$ref": "#/$defs/string_set" },
                    "source_scopes": { "$ref": "#/$defs/string_set" },
                    "perspectives": { "$ref": "#/$defs/string_set" },
                    "known_units": { "$ref": "#/$defs/semantic_id_set" },
                    "authority_context": { "$ref": "#/$defs/authority_context" },
                    "budget": { "$ref": "#/$defs/query_budget" }
                }
            },
            "protocol_operation": {
                "oneOf": [
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["operation", "query"],
                        "properties": {
                            "operation": { "const": "query" },
                            "query": { "$ref": "#/$defs/query_request" }
                        }
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["operation", "inspect"],
                        "properties": {
                            "operation": { "const": "inspect" },
                            "inspect": {
                                "oneOf": [
                                    {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": ["target"],
                                        "properties": { "target": { "const": "fabric" } }
                                    },
                                    {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": ["target", "package_id"],
                                        "properties": {
                                            "target": { "enum": ["package", "certificate"] },
                                            "package_id": { "$ref": "#/$defs/semantic_id" }
                                        }
                                    },
                                    {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "required": ["target", "unit_id"],
                                        "properties": {
                                            "target": { "const": "semantic_unit" },
                                            "unit_id": { "$ref": "#/$defs/semantic_id" }
                                        }
                                    }
                                ]
                            }
                        }
                    }
                ]
            },
            "protocol_request": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "protocol_version", "request_id", "caller_context",
                    "expected_environment_digest", "expected_packages",
                    "requested_scope", "request"
                ],
                "properties": {
                    "protocol_version": { "type": "string", "const": "cantor-protocol/0.1" },
                    "request_id": { "$ref": "#/$defs/semantic_id" },
                    "caller_context": { "$ref": "#/$defs/caller_context" },
                    "expected_environment_digest": { "$ref": "#/$defs/digest" },
                    "expected_packages": {
                        "type": "array",
                        "items": { "$ref": "#/$defs/expected_package" }
                    },
                    "requested_scope": { "$ref": "#/$defs/authority_scope" },
                    "request": { "$ref": "#/$defs/protocol_operation" }
                }
            }
        }
    }))
}

fn output_schema() -> JsonObject {
    object(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "protocol_version",
            "request_id",
            "operation",
            "status",
            "exit_class",
            "result",
            "faults",
            "proof",
            "continuation"
        ],
        "properties": {
            "protocol_version": { "type": "string" },
            "request_id": { "type": "string" },
            "operation": { "type": "string" },
            "status": { "type": "string", "enum": ["success", "partial", "fault"] },
            "exit_class": { "type": "string" },
            "result": { "type": "object" },
            "faults": { "type": "array" },
            "proof": { "type": "object" },
            "continuation": { "type": "string", "enum": ["finish", "query_or_reframe", "stop"] }
        }
    }))
}
