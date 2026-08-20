//! Read-only MCP projection of Cantor's deterministic protocol.
//!
//! This crate is intentionally an adapter, not another semantic authority.
//! Embedded mode exposes signed query and lexical anchor-discovery tools;
//! resident-service mode preserves the signed query tool alone. Every valid
//! operation delegates its semantics and proof construction to `cantor_core`.

#![recursion_limit = "512"]

use std::{fmt, fs::File, io::Read, path::Path, sync::Arc};

use cantor_core::{
    CatalogueDerivationRequest, ContentDigest, DerivedLexicalAssociationIndex,
    DerivedSemanticAnchorCatalogue, EmbeddedRuntimeEnvironment, LEXICAL_ANCHOR_LOOKUP_PROFILE,
    LEXICAL_TOKENIZER_PROFILE, LexicalAnchorLookupBudget, LexicalAnchorLookupRequest,
    LexicalAnchorLookupResult, LexicalAnchorSourceProjectionBudget,
    LexicalAnchorSourceProjectionResult, LexicalIndexDerivationRequest, MAX_LEXICAL_LOOKUP_MATCHES,
    MAX_LEXICAL_LOOKUP_POSTINGS, MAX_LEXICAL_SURFACE_BYTES, PreparedRuntime, ProtocolRequest,
    ProtocolResponse, ProtocolStatus, SemanticFabric, SemanticId, admit_package,
    derive_lexical_association_index, derive_semantic_anchor_catalogue, lookup_lexical_anchors,
    preflight_runtime_environment, project_lexical_anchor_sources, sha256_bytes,
};
use cantor_service::{
    ServiceClient, ServiceDisposition, ServiceOperation, ServiceResponse, ServiceResult,
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

pub const TOOL_NAME: &str = "query_sop";
pub const ANCHOR_TOOL_NAME: &str = "lookup_sop_anchors";
pub const ADAPTER_PROTOCOL_VERSION: &str = "cantor-mcp-adapter/0.1";
pub const MAX_ARGUMENT_BYTES: usize = 1_048_576;
pub const MAX_ENVIRONMENT_BYTES: usize = 67_108_864;

#[derive(Clone, Debug)]
pub struct CantorMcpServer {
    backend: RuntimeBackend,
    anchor_runtime: Option<Arc<AnchorLookupRuntime>>,
}

#[derive(Clone, Debug)]
struct AnchorLookupRuntime {
    environment_digest: ContentDigest,
    fabric: SemanticFabric,
    catalogue: DerivedSemanticAnchorCatalogue,
    index: DerivedLexicalAssociationIndex,
}

#[derive(Clone, Debug)]
enum RuntimeBackend {
    Embedded(Arc<PreparedRuntime>),
    Resident(Arc<ServiceClient>),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupSopAnchorsArguments {
    text: String,
    #[serde(default = "default_include_source")]
    include_source: bool,
    #[serde(default = "default_maximum_postings")]
    maximum_postings: u32,
    #[serde(default = "default_maximum_matches")]
    maximum_matches: u32,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AnchorLookupToolResult {
    adapter_protocol_version: &'static str,
    status: &'static str,
    environment_digest: ContentDigest,
    result: LexicalAnchorLookupResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_projection: Option<LexicalAnchorSourceProjectionResult>,
}

impl AnchorLookupRuntime {
    fn prepare(
        environment: &EmbeddedRuntimeEnvironment,
        environment_digest: ContentDigest,
    ) -> Result<Self, StartupFault> {
        let mut admitted = Vec::with_capacity(environment.packages.len());
        for package in &environment.packages {
            let certificate = package.certificate.as_ref().ok_or_else(|| StartupFault {
                code: "anchor_package_missing_certificate",
                message: bounded_message(&format!(
                    "package {} has no recognition certificate",
                    package.package_id
                )),
            })?;
            admitted.push(
                admit_package(
                    package,
                    &environment.trust_store,
                    &certificate.authority_scope,
                    environment.now_epoch_seconds,
                )
                .map_err(|fault| StartupFault {
                    code: "anchor_package_admission_failed",
                    message: bounded_message(&fault.message),
                })?,
            );
        }
        let fabric = SemanticFabric::from_admitted(admitted).map_err(|fault| StartupFault {
            code: "anchor_fabric_initialization_failed",
            message: bounded_message(&format!("{fault:?}")),
        })?;
        let logical_revision = format!("environment:{}", environment_digest.value);
        let catalogue = derive_semantic_anchor_catalogue(
            &fabric,
            CatalogueDerivationRequest {
                catalogue_id: static_semantic_id("catalogue:cantor_mcp_anchor_lookup"),
                logical_revision: logical_revision.clone(),
            },
        )
        .map_err(|fault| StartupFault {
            code: "anchor_catalogue_derivation_failed",
            message: bounded_message(&format!("{}: {}", fault.stage, fault.detail)),
        })?;
        let index = derive_lexical_association_index(
            &fabric,
            &catalogue,
            LexicalIndexDerivationRequest {
                index_id: static_semantic_id("lexical-index:cantor_mcp_anchor_lookup"),
                logical_revision,
                tokenizer_profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
            },
        )
        .map_err(|fault| StartupFault {
            code: "anchor_index_derivation_failed",
            message: bounded_message(&format!("{}: {}", fault.field, fault.detail)),
        })?;
        Ok(Self {
            environment_digest,
            fabric,
            catalogue,
            index,
        })
    }
}

impl CantorMcpServer {
    pub fn new(environment: EmbeddedRuntimeEnvironment) -> Result<Self, StartupFault> {
        let environment_digest = preflight_environment(&environment)?;
        let anchor_runtime = AnchorLookupRuntime::prepare(&environment, environment_digest)?;
        let runtime = PreparedRuntime::new(environment).map_err(|fault| StartupFault {
            code: "prepared_runtime_initialization_failed",
            message: bounded_message(&fault.to_string()),
        })?;
        Ok(Self {
            backend: RuntimeBackend::Embedded(Arc::new(runtime)),
            anchor_runtime: Some(Arc::new(anchor_runtime)),
        })
    }

    pub fn from_service_config(config_path: &Path) -> Result<Self, StartupFault> {
        let client =
            Arc::new(ServiceClient::from_config(config_path).map_err(service_startup_fault)?);
        let status_id = SemanticId::new("request:mcp_resident_startup")
            .unwrap_or_else(|_| unreachable!("static startup identity is valid"));
        let response = client
            .send(ServiceOperation::Status, status_id)
            .map_err(service_startup_fault)?;
        require_status_result(&response)?;
        Ok(Self {
            backend: RuntimeBackend::Resident(client),
            anchor_runtime: None,
        })
    }

    pub fn environment(&self) -> Option<&EmbeddedRuntimeEnvironment> {
        self.runtime().map(PreparedRuntime::environment)
    }

    /// Returns the process-local runtime only when embedded mode owns one.
    pub fn runtime(&self) -> Option<&PreparedRuntime> {
        match &self.backend {
            RuntimeBackend::Embedded(runtime) => Some(runtime),
            RuntimeBackend::Resident(_) => None,
        }
    }

    pub fn is_resident_backed(&self) -> bool {
        matches!(self.backend, RuntimeBackend::Resident(_))
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

    pub fn anchor_tool_definition() -> Tool {
        Tool::new(
            ANCHOR_TOOL_NAME,
            "Map ordinary text to ordered proof-bearing anchors in the active signed SOP environment. Exact admitted source quotations are included by default. Results are lexical evidence and signed-snapshot correspondence, not truth, permission, authority, safety, or applicability decisions.",
            anchor_input_schema(),
        )
        .with_title("Lookup signed SOP anchors")
        .with_raw_output_schema(Arc::new(anchor_output_schema()))
        .with_annotations(
            ToolAnnotations::with_title("Lookup signed SOP anchors")
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
        match &self.backend {
            RuntimeBackend::Embedded(runtime) => protocol_result(runtime.execute(parsed.request)),
            RuntimeBackend::Resident(client) => {
                let request_id = parsed.request.request_id.clone();
                match client.send(
                    ServiceOperation::Execute {
                        request: Box::new(parsed.request),
                    },
                    request_id,
                ) {
                    Ok(response) => service_protocol_result(response),
                    Err(fault) => adapter_fault(
                        "resident_service_transport_fault",
                        bounded_message(&fault.to_string()),
                    ),
                }
            }
        }
    }

    pub fn execute_anchor_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let Some(runtime) = &self.anchor_runtime else {
            return adapter_fault(
                "anchor_lookup_unavailable",
                "lookup_sop_anchors is available only with an embedded signed environment"
                    .to_owned(),
            );
        };
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
        let parsed: LookupSopAnchorsArguments = match serde_json::from_value(argument_value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return adapter_fault("invalid_arguments", bounded_message(&error.to_string()));
            }
        };
        let request_digest = sha256_bytes(parsed.text.as_bytes());
        let request_id = match SemanticId::new(format!(
            "request:mcp_anchor_lookup:{}",
            request_digest.value
        )) {
            Ok(request_id) => request_id,
            Err(fault) => {
                return adapter_fault("request_identity_failed", bounded_message(&fault.message));
            }
        };
        let request = LexicalAnchorLookupRequest {
            profile: LEXICAL_ANCHOR_LOOKUP_PROFILE.to_owned(),
            request_id,
            terms: vec![parsed.text],
            budget: LexicalAnchorLookupBudget {
                maximum_terms: 1,
                maximum_query_bytes: 65_536,
                maximum_unique_tokens: 4_096,
                maximum_postings: parsed.maximum_postings,
                maximum_matches: parsed.maximum_matches,
                maximum_serialized_result_bytes: 16 * 1024 * 1024,
            },
        };
        let result = match lookup_lexical_anchors(
            &runtime.fabric,
            &runtime.catalogue,
            &runtime.index,
            request.clone(),
        ) {
            Ok(result) => result,
            Err(fault) => {
                return adapter_fault(
                    "anchor_lookup_failed",
                    bounded_message(&format!("{}: {}", fault.field, fault.detail)),
                );
            }
        };
        let source_projection = if parsed.include_source {
            match project_lexical_anchor_sources(
                &runtime.fabric,
                &runtime.catalogue,
                &runtime.index,
                &request,
                &result,
                LexicalAnchorSourceProjectionBudget {
                    maximum_projections: parsed.maximum_matches,
                    maximum_quote_bytes: 16 * 1024 * 1024,
                    maximum_serialized_result_bytes: 32 * 1024 * 1024,
                },
            ) {
                Ok(projection) => Some(projection),
                Err(fault) => {
                    return adapter_fault(
                        "anchor_source_projection_failed",
                        bounded_message(&format!("{}: {}", fault.field, fault.detail)),
                    );
                }
            }
        } else {
            None
        };
        let match_count = result.matches.len();
        let projection_count = source_projection
            .as_ref()
            .map_or(0, |projection| projection.projections.len());
        let value = match serde_json::to_value(AnchorLookupToolResult {
            adapter_protocol_version: ADAPTER_PROTOCOL_VERSION,
            status: "success",
            environment_digest: runtime.environment_digest.clone(),
            result,
            source_projection,
        }) {
            Ok(value) => value,
            Err(error) => {
                return adapter_fault(
                    "response_encoding_failed",
                    bounded_message(&error.to_string()),
                );
            }
        };
        structured_result(
            value,
            false,
            format!(
                "Cantor anchor lookup success; matches={match_count}; source_projections={projection_count}."
            ),
        )
    }
}

impl ServerHandler for CantorMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor signed semantic coprocessor")
                    .with_description(
                        "Read-only access to an operator-selected signed SOP runtime through one deterministic tool.",
                    ),
            )
            .with_instructions(
                "Use lookup_sop_anchors to discover exact signed SOP records and quotations from ordinary text when that tool is advertised. Treat its lexical and snapshot-boundary statements as mandatory. Use query_sop only when a trusted supervisor has supplied a complete ProtocolRequest template; never guess caller identity, package bindings, environment digest, scope, permission, or authority. Treat structuredContent as authoritative and preserve every fault and proof boundary.",
            )
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        match name {
            TOOL_NAME => Some(Self::tool_definition()),
            ANCHOR_TOOL_NAME if self.anchor_runtime.is_some() => {
                Some(Self::anchor_tool_definition())
            }
            _ => None,
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = vec![Self::tool_definition()];
        if self.anchor_runtime.is_some() {
            tools.push(Self::anchor_tool_definition());
        }
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        match request.name.as_ref() {
            TOOL_NAME => Ok(self.execute_tool_arguments(request.arguments).into()),
            ANCHOR_TOOL_NAME if self.anchor_runtime.is_some() => {
                Ok(self.execute_anchor_tool_arguments(request.arguments).into())
            }
            _ => Err(McpError::method_not_found::<CallToolRequestMethod>()),
        }
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

fn preflight_environment(
    environment: &EmbeddedRuntimeEnvironment,
) -> Result<ContentDigest, StartupFault> {
    preflight_runtime_environment(environment).map_err(|fault| StartupFault {
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

fn service_protocol_result(response: ServiceResponse) -> CallToolResult {
    if response.disposition == ServiceDisposition::Fault {
        let message = response
            .faults
            .first()
            .map(ToString::to_string)
            .unwrap_or_else(|| "resident service returned a fault without detail".to_owned());
        return adapter_fault("resident_service_fault", bounded_message(&message));
    }
    match response.result {
        Some(ServiceResult::Protocol { response }) => protocol_result(*response),
        _ => adapter_fault(
            "unexpected_resident_service_result",
            "resident service execute did not return a protocol result".to_owned(),
        ),
    }
}

fn require_status_result(response: &ServiceResponse) -> Result<(), StartupFault> {
    if response.disposition == ServiceDisposition::Success
        && matches!(response.result, Some(ServiceResult::Status { .. }))
    {
        return Ok(());
    }
    let message = response
        .faults
        .first()
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            "resident service startup probe returned an unexpected result".to_owned()
        });
    Err(StartupFault {
        code: "resident_service_unready",
        message: bounded_message(&message),
    })
}

fn service_startup_fault(fault: cantor_service::ServiceFault) -> StartupFault {
    StartupFault {
        code: "resident_service_unready",
        message: bounded_message(&fault.to_string()),
    }
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

const fn default_include_source() -> bool {
    true
}

const fn default_maximum_postings() -> u32 {
    16_384
}

const fn default_maximum_matches() -> u32 {
    256
}

fn static_semantic_id(value: &str) -> SemanticId {
    SemanticId::new(value).unwrap_or_else(|_| unreachable!("static MCP semantic identity is valid"))
}

fn object(value: Value) -> JsonObject {
    value
        .as_object()
        .expect("static schema must be a JSON object")
        .clone()
}

fn anchor_input_schema() -> JsonObject {
    object(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["text"],
        "properties": {
            "text": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_LEXICAL_SURFACE_BYTES,
                "description": "Ordinary text whose lexical tokens should be resolved against the active signed SOP generation."
            },
            "include_source": {
                "type": "boolean",
                "default": true,
                "description": "Include exact admitted snapshot paths, line spans, quotations, certificate identities, and source-projection proofs."
            },
            "maximum_postings": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_LEXICAL_LOOKUP_POSTINGS,
                "default": 16_384
            },
            "maximum_matches": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_LEXICAL_LOOKUP_MATCHES,
                "default": 256
            }
        }
    }))
}

fn anchor_output_schema() -> JsonObject {
    object(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "adapter_protocol_version", "status", "environment_digest", "result"
        ],
        "properties": {
            "adapter_protocol_version": { "type": "string", "const": ADAPTER_PROTOCOL_VERSION },
            "status": { "type": "string", "const": "success" },
            "environment_digest": { "type": "object" },
            "result": { "type": "object" },
            "source_projection": { "type": "object" }
        }
    }))
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
