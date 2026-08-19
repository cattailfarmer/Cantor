//! Volatile compact-handle custody for resumable procedure coordination.
//!
//! The pure registry stores exact typed context plus checkpoint or outcome.
//! The MCP adapter serializes transitions and exposes bounded JSON strings so
//! its model-facing schema does not recursively expand the runtime graph.

#![recursion_limit = "512"]

use std::{collections::BTreeMap, sync::Arc};

use cantor_core::{
    ContentDigest, CoordinationCheckpoint, CoordinationOutcome, SemanticId, sha256_bytes,
    validate_coordination_checkpoint,
};
use cantor_procedure_tool::{
    CoordinationToolContext, CoordinationToolRequest, CoordinationToolResult,
    CoordinationToolStatus, execute_coordination_tool_request,
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

pub const REGISTRY_PROFILE: &str = "cantor-compact-coordination-registry/0.1";
pub const HANDLE_PROFILE: &str = "cantor-compact-coordination-handle/0.1";
pub const RESPONSE_PROFILE: &str = "cantor-compact-coordination-session/0.1";
pub const TOOL_NAME: &str = "continue_procedure_session";
pub const MAX_ARGUMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CONTEXT_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_REGISTRY_ID: &str = "registry:compact-coordination-local";
pub const SERVER_INSTRUCTIONS: &str = "OPEN imports one exact typed context JSON string and returns a compact handle. ADVANCE requires the current registry digest, session id, sequence, record digest, and a positive quota. INSPECT returns the handle; READ returns exact retained record JSON. Preserve every digest. This process stores context and checkpoints only in volatile memory; restart loses all sessions. It invokes no model, performs no external effect, and does not authenticate digest producers.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompactSessionStatus {
    Ready,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactCoordinationRecord {
    pub session_id: SemanticId,
    pub sequence: u64,
    pub context: Box<CoordinationToolContext>,
    pub checkpoint: Option<Box<CoordinationCheckpoint>>,
    pub outcome: Option<Box<CoordinationOutcome>>,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactCoordinationRegistry {
    pub profile: String,
    pub registry_id: SemanticId,
    pub generation: u64,
    pub sessions: BTreeMap<SemanticId, CompactCoordinationRecord>,
    pub registry_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompactCoordinationHandle {
    pub profile: String,
    pub registry_id: SemanticId,
    pub registry_digest: ContentDigest,
    pub session_id: SemanticId,
    pub sequence: u64,
    pub record_digest: ContentDigest,
    pub status: CompactSessionStatus,
    pub checkpoint_digest: Option<ContentDigest>,
    pub outcome_digest: Option<ContentDigest>,
    pub handle_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompactSessionOperation {
    Open,
    Advance,
    Inspect,
    Read,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompactSessionCommand {
    Open {
        expected_registry_digest: ContentDigest,
        session_id: SemanticId,
        context_json: String,
    },
    Advance {
        expected_registry_digest: ContentDigest,
        session_id: SemanticId,
        expected_sequence: u64,
        expected_record_digest: ContentDigest,
        maximum_steps: u64,
    },
    Inspect {
        expected_registry_digest: ContentDigest,
        session_id: SemanticId,
    },
    Read {
        expected_registry_digest: ContentDigest,
        session_id: SemanticId,
    },
}

impl CompactSessionCommand {
    const fn operation(&self) -> CompactSessionOperation {
        match self {
            Self::Open { .. } => CompactSessionOperation::Open,
            Self::Advance { .. } => CompactSessionOperation::Advance,
            Self::Inspect { .. } => CompactSessionOperation::Inspect,
            Self::Read { .. } => CompactSessionOperation::Read,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompactResponseStatus {
    Succeeded,
    Refused,
    InvalidRequest,
    InternalFault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompactSessionFault {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompactSessionResult {
    State {
        handle: CompactCoordinationHandle,
    },
    Record {
        handle: CompactCoordinationHandle,
        record_json: String,
        record_digest: ContentDigest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompactSessionResponse {
    pub profile: String,
    pub operation: CompactSessionOperation,
    pub status: CompactResponseStatus,
    pub result: Option<CompactSessionResult>,
    pub fault: Option<CompactSessionFault>,
    pub nonclaims: Vec<String>,
}

impl CompactSessionResponse {
    #[must_use]
    pub const fn is_error(&self) -> bool {
        !matches!(self.status, CompactResponseStatus::Succeeded)
    }

    fn success(operation: CompactSessionOperation, result: CompactSessionResult) -> Self {
        Self {
            profile: RESPONSE_PROFILE.to_owned(),
            operation,
            status: CompactResponseStatus::Succeeded,
            result: Some(result),
            fault: None,
            nonclaims: nonclaims(),
        }
    }

    fn failed(
        operation: CompactSessionOperation,
        status: CompactResponseStatus,
        code: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self {
            profile: RESPONSE_PROFILE.to_owned(),
            operation,
            status,
            result: None,
            fault: Some(CompactSessionFault {
                code: code.into(),
                message: bounded(message.as_ref()),
            }),
            nonclaims: nonclaims(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactSessionTransition {
    pub successor: CompactCoordinationRegistry,
    pub response: CompactSessionResponse,
}

pub fn new_compact_coordination_registry(
    registry_id: SemanticId,
) -> Result<CompactCoordinationRegistry, String> {
    let mut registry = CompactCoordinationRegistry {
        profile: REGISTRY_PROFILE.to_owned(),
        registry_id,
        generation: 0,
        sessions: BTreeMap::new(),
        registry_digest: empty_digest(),
    };
    registry.registry_digest = registry_digest(&registry)?;
    Ok(registry)
}

pub fn validate_compact_coordination_registry(
    registry: &CompactCoordinationRegistry,
) -> Result<(), String> {
    if registry.profile != REGISTRY_PROFILE {
        return Err("compact registry profile is not recognized".to_owned());
    }
    if registry.registry_digest != registry_digest(registry)? {
        return Err("compact registry digest mismatch".to_owned());
    }
    for (session_id, record) in &registry.sessions {
        if session_id != &record.session_id || record.sequence == 0 {
            return Err("compact record identity or sequence is invalid".to_owned());
        }
        if record.record_digest != record_digest(record)? {
            return Err("compact record digest mismatch".to_owned());
        }
        match (&record.checkpoint, &record.outcome) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => return Err("compact record must carry exactly one state value".to_owned()),
        }
        if let Some(checkpoint) = &record.checkpoint {
            validate_coordination_checkpoint(
                &record.context.catalogue,
                &record.context.procedure,
                &record.context.ir,
                &record.context.admission,
                &record.context.request,
                &record.context.initial_session,
                checkpoint,
            )
            .map_err(|fault| format!("retained checkpoint is invalid: {fault}"))?;
        }
        if let Some(outcome) = &record.outcome
            && (outcome.result.invocation_ref != record.context.request.invocation_id
                || outcome.result.procedure_ref != record.context.procedure.procedure_id)
        {
            return Err("terminal outcome identity differs from retained context".to_owned());
        }
    }
    Ok(())
}

#[must_use]
pub fn apply_compact_coordination_command(
    registry: &CompactCoordinationRegistry,
    command: CompactSessionCommand,
) -> CompactSessionTransition {
    let operation = command.operation();
    if let Err(message) = validate_compact_coordination_registry(registry) {
        return unchanged(
            registry,
            CompactSessionResponse::failed(
                operation,
                CompactResponseStatus::InternalFault,
                "invalid_registry",
                message,
            ),
        );
    }
    let expected = match &command {
        CompactSessionCommand::Open {
            expected_registry_digest,
            ..
        }
        | CompactSessionCommand::Advance {
            expected_registry_digest,
            ..
        }
        | CompactSessionCommand::Inspect {
            expected_registry_digest,
            ..
        }
        | CompactSessionCommand::Read {
            expected_registry_digest,
            ..
        } => expected_registry_digest,
    };
    if expected != &registry.registry_digest {
        return unchanged(
            registry,
            CompactSessionResponse::failed(
                operation,
                CompactResponseStatus::Refused,
                "stale_registry",
                "expected registry digest does not match current state",
            ),
        );
    }
    match command {
        CompactSessionCommand::Open {
            session_id,
            context_json,
            ..
        } => open_session(registry, session_id, context_json),
        CompactSessionCommand::Advance {
            session_id,
            expected_sequence,
            expected_record_digest,
            maximum_steps,
            ..
        } => advance_session(
            registry,
            session_id,
            expected_sequence,
            expected_record_digest,
            maximum_steps,
        ),
        CompactSessionCommand::Inspect { session_id, .. } => {
            inspect_session(registry, session_id, false)
        }
        CompactSessionCommand::Read { session_id, .. } => {
            inspect_session(registry, session_id, true)
        }
    }
}

fn open_session(
    registry: &CompactCoordinationRegistry,
    session_id: SemanticId,
    context_json: String,
) -> CompactSessionTransition {
    if context_json.len() > MAX_CONTEXT_JSON_BYTES {
        return unchanged(
            registry,
            CompactSessionResponse::failed(
                CompactSessionOperation::Open,
                CompactResponseStatus::InvalidRequest,
                "context_limit_exceeded",
                "context_json exceeds the 4194304-byte limit",
            ),
        );
    }
    if registry.sessions.contains_key(&session_id) {
        return unchanged(
            registry,
            CompactSessionResponse::failed(
                CompactSessionOperation::Open,
                CompactResponseStatus::Refused,
                "duplicate_session",
                "session identity is already present",
            ),
        );
    }
    let context: CoordinationToolContext = match serde_json::from_str(&context_json) {
        Ok(context) => context,
        Err(error) => {
            return unchanged(
                registry,
                CompactSessionResponse::failed(
                    CompactSessionOperation::Open,
                    CompactResponseStatus::InvalidRequest,
                    "invalid_context_json",
                    error.to_string(),
                ),
            );
        }
    };
    let response = execute_coordination_tool_request(CoordinationToolRequest::Begin {
        context: Box::new(context.clone()),
    });
    let checkpoint = match response.result {
        Some(CoordinationToolResult::Began { checkpoint })
            if response.status == CoordinationToolStatus::Succeeded =>
        {
            checkpoint
        }
        _ => {
            return unchanged(
                registry,
                CompactSessionResponse::failed(
                    CompactSessionOperation::Open,
                    CompactResponseStatus::Refused,
                    "coordination_begin_refused",
                    response
                        .fault
                        .map_or_else(|| "core BEGIN returned no result".to_owned(), |f| f.message),
                ),
            );
        }
    };
    let mut record = CompactCoordinationRecord {
        session_id: session_id.clone(),
        sequence: 1,
        context: Box::new(context),
        checkpoint: Some(checkpoint),
        outcome: None,
        record_digest: empty_digest(),
    };
    if let Err(error) = finalize_record(&mut record) {
        return internal_unchanged(registry, CompactSessionOperation::Open, error);
    }
    mutate_registry(registry, record, CompactSessionOperation::Open)
}

fn advance_session(
    registry: &CompactCoordinationRegistry,
    session_id: SemanticId,
    expected_sequence: u64,
    expected_record_digest: ContentDigest,
    maximum_steps: u64,
) -> CompactSessionTransition {
    if maximum_steps == 0 {
        return unchanged(
            registry,
            CompactSessionResponse::failed(
                CompactSessionOperation::Advance,
                CompactResponseStatus::InvalidRequest,
                "zero_step_quota",
                "maximum_steps must be greater than zero",
            ),
        );
    }
    let Some(current) = registry.sessions.get(&session_id) else {
        return unknown_session(registry, CompactSessionOperation::Advance);
    };
    if current.sequence != expected_sequence || current.record_digest != expected_record_digest {
        return unchanged(
            registry,
            CompactSessionResponse::failed(
                CompactSessionOperation::Advance,
                CompactResponseStatus::Refused,
                "stale_session",
                "expected sequence or record digest does not match current state",
            ),
        );
    }
    let Some(checkpoint) = current.checkpoint.as_ref() else {
        return unchanged(
            registry,
            CompactSessionResponse::failed(
                CompactSessionOperation::Advance,
                CompactResponseStatus::Refused,
                "terminal_session",
                "terminal session cannot advance",
            ),
        );
    };
    let core = execute_coordination_tool_request(CoordinationToolRequest::Advance {
        context: current.context.clone(),
        checkpoint: checkpoint.clone(),
        maximum_steps,
    });
    let transition = match core.result {
        Some(CoordinationToolResult::Advanced { transition })
            if core.status == CoordinationToolStatus::Succeeded =>
        {
            transition
        }
        _ => {
            return unchanged(
                registry,
                CompactSessionResponse::failed(
                    CompactSessionOperation::Advance,
                    CompactResponseStatus::Refused,
                    "coordination_advance_refused",
                    core.fault.map_or_else(
                        || "core ADVANCE returned no result".to_owned(),
                        |f| f.message,
                    ),
                ),
            );
        }
    };
    let next_sequence = match current.sequence.checked_add(1) {
        Some(value) => value,
        None => {
            return internal_unchanged(
                registry,
                CompactSessionOperation::Advance,
                "session sequence overflow",
            );
        }
    };
    let (checkpoint, outcome) = match (transition.checkpoint, transition.outcome) {
        (Some(checkpoint), None) => (Some(Box::new(checkpoint)), None),
        (None, Some(outcome)) => (None, Some(Box::new(outcome))),
        _ => {
            return internal_unchanged(
                registry,
                CompactSessionOperation::Advance,
                "core transition carried invalid state shape",
            );
        }
    };
    let mut record = CompactCoordinationRecord {
        session_id,
        sequence: next_sequence,
        context: current.context.clone(),
        checkpoint,
        outcome,
        record_digest: empty_digest(),
    };
    if let Err(error) = finalize_record(&mut record) {
        return internal_unchanged(registry, CompactSessionOperation::Advance, error);
    }
    mutate_registry(registry, record, CompactSessionOperation::Advance)
}

fn inspect_session(
    registry: &CompactCoordinationRegistry,
    session_id: SemanticId,
    read: bool,
) -> CompactSessionTransition {
    let operation = if read {
        CompactSessionOperation::Read
    } else {
        CompactSessionOperation::Inspect
    };
    let Some(record) = registry.sessions.get(&session_id) else {
        return unknown_session(registry, operation);
    };
    let handle = match handle_from_record(registry, record) {
        Ok(handle) => handle,
        Err(error) => return internal_unchanged(registry, operation, error),
    };
    let result = if read {
        match serde_json::to_string(record) {
            Ok(record_json) => CompactSessionResult::Record {
                handle,
                record_json,
                record_digest: record.record_digest.clone(),
            },
            Err(error) => return internal_unchanged(registry, operation, error.to_string()),
        }
    } else {
        CompactSessionResult::State { handle }
    };
    unchanged(registry, CompactSessionResponse::success(operation, result))
}

fn mutate_registry(
    registry: &CompactCoordinationRegistry,
    record: CompactCoordinationRecord,
    operation: CompactSessionOperation,
) -> CompactSessionTransition {
    let session_id = record.session_id.clone();
    let mut successor = registry.clone();
    successor.generation = match successor.generation.checked_add(1) {
        Some(value) => value,
        None => return internal_unchanged(registry, operation, "registry generation overflow"),
    };
    successor.sessions.insert(session_id.clone(), record);
    successor.registry_digest = match registry_digest(&successor) {
        Ok(digest) => digest,
        Err(error) => return internal_unchanged(registry, operation, error),
    };
    if let Err(error) = validate_compact_coordination_registry(&successor) {
        return internal_unchanged(registry, operation, error);
    }
    let Some(record) = successor.sessions.get(&session_id) else {
        return internal_unchanged(registry, operation, "mutated record is missing");
    };
    let handle = match handle_from_record(&successor, record) {
        Ok(handle) => handle,
        Err(error) => return internal_unchanged(registry, operation, error),
    };
    CompactSessionTransition {
        successor,
        response: CompactSessionResponse::success(
            operation,
            CompactSessionResult::State { handle },
        ),
    }
}

fn handle_from_record(
    registry: &CompactCoordinationRegistry,
    record: &CompactCoordinationRecord,
) -> Result<CompactCoordinationHandle, String> {
    let (status, checkpoint_digest, outcome_digest) = match (&record.checkpoint, &record.outcome) {
        (Some(checkpoint), None) => (
            CompactSessionStatus::Ready,
            Some(checkpoint.checkpoint_digest.clone()),
            None,
        ),
        (None, Some(outcome)) => (
            CompactSessionStatus::Terminal,
            None,
            Some(digest_value(outcome.as_ref())?),
        ),
        _ => return Err("record has invalid state shape".to_owned()),
    };
    let mut handle = CompactCoordinationHandle {
        profile: HANDLE_PROFILE.to_owned(),
        registry_id: registry.registry_id.clone(),
        registry_digest: registry.registry_digest.clone(),
        session_id: record.session_id.clone(),
        sequence: record.sequence,
        record_digest: record.record_digest.clone(),
        status,
        checkpoint_digest,
        outcome_digest,
        handle_digest: empty_digest(),
    };
    handle.handle_digest = handle_digest(&handle)?;
    Ok(handle)
}

fn finalize_record(record: &mut CompactCoordinationRecord) -> Result<(), String> {
    record.record_digest = record_digest(record)?;
    Ok(())
}

fn record_digest(record: &CompactCoordinationRecord) -> Result<ContentDigest, String> {
    let mut unsigned = record.clone();
    unsigned.record_digest = empty_digest();
    digest_value(&unsigned)
}

fn registry_digest(registry: &CompactCoordinationRegistry) -> Result<ContentDigest, String> {
    let mut unsigned = registry.clone();
    unsigned.registry_digest = empty_digest();
    digest_value(&unsigned)
}

fn handle_digest(handle: &CompactCoordinationHandle) -> Result<ContentDigest, String> {
    let mut unsigned = handle.clone();
    unsigned.handle_digest = empty_digest();
    digest_value(&unsigned)
}

fn digest_value<T: Serialize>(value: &T) -> Result<ContentDigest, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn unchanged(
    registry: &CompactCoordinationRegistry,
    response: CompactSessionResponse,
) -> CompactSessionTransition {
    CompactSessionTransition {
        successor: registry.clone(),
        response,
    }
}

fn unknown_session(
    registry: &CompactCoordinationRegistry,
    operation: CompactSessionOperation,
) -> CompactSessionTransition {
    unchanged(
        registry,
        CompactSessionResponse::failed(
            operation,
            CompactResponseStatus::Refused,
            "unknown_session",
            "session identity is not present",
        ),
    )
}

fn internal_unchanged(
    registry: &CompactCoordinationRegistry,
    operation: CompactSessionOperation,
    message: impl AsRef<str>,
) -> CompactSessionTransition {
    unchanged(
        registry,
        CompactSessionResponse::failed(
            operation,
            CompactResponseStatus::InternalFault,
            "internal_fault",
            message,
        ),
    )
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn nonclaims() -> Vec<String> {
    vec![
        "registry state is process-local and restart loses every session".to_owned(),
        "digest binding does not authenticate a producer or prove semantic truth".to_owned(),
        "no model provider prompt hidden state or external effect was accessed".to_owned(),
        "no durable persistence or production authority is claimed".to_owned(),
    ]
}

fn bounded(message: &str) -> String {
    message.chars().take(1024).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompactSessionArguments {
    pub request: CompactSessionCommand,
}

#[derive(Clone, Debug)]
pub struct CompactCoordinationMcpServer {
    registry: Arc<Mutex<CompactCoordinationRegistry>>,
}

impl CompactCoordinationMcpServer {
    pub fn new(registry_id: SemanticId) -> Result<Self, String> {
        Ok(Self {
            registry: Arc::new(Mutex::new(new_compact_coordination_registry(registry_id)?)),
        })
    }

    pub fn local() -> Result<Self, String> {
        let registry_id =
            SemanticId::new(DEFAULT_REGISTRY_ID).map_err(|fault| fault.to_string())?;
        Self::new(registry_id)
    }

    pub async fn snapshot(&self) -> CompactCoordinationRegistry {
        self.registry.lock().await.clone()
    }

    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Open, advance, inspect, or read one volatile content-addressed procedure session. OPEN imports exact context JSON once; ordinary ADVANCE uses only compact compare-and-set identities and a quota.",
            schema_object::<CompactSessionArguments>(),
        )
        .with_title("Continue compact Cantor procedure session")
        .with_raw_output_schema(Arc::new(schema_object::<CompactSessionResponse>()))
        .with_annotations(
            ToolAnnotations::with_title("Continue compact Cantor procedure session")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        )
    }

    pub async fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let value = Value::Object(arguments.unwrap_or_default());
        let operation = operation_hint(&value);
        let encoded = match serde_json::to_vec(&value) {
            Ok(encoded) => encoded,
            Err(error) => {
                return response_result(CompactSessionResponse::failed(
                    operation,
                    CompactResponseStatus::InternalFault,
                    "argument_encoding_failed",
                    error.to_string(),
                ));
            }
        };
        if encoded.len() > MAX_ARGUMENT_BYTES {
            return response_result(CompactSessionResponse::failed(
                operation,
                CompactResponseStatus::InvalidRequest,
                "argument_limit_exceeded",
                format!(
                    "tool arguments contain {} bytes; maximum is {MAX_ARGUMENT_BYTES}",
                    encoded.len()
                ),
            ));
        }
        let arguments: CompactSessionArguments = match serde_json::from_value(value) {
            Ok(arguments) => arguments,
            Err(error) => {
                return response_result(CompactSessionResponse::failed(
                    operation,
                    CompactResponseStatus::InvalidRequest,
                    "invalid_arguments",
                    error.to_string(),
                ));
            }
        };
        let mut registry = self.registry.lock().await;
        let transition = apply_compact_coordination_command(&registry, arguments.request);
        *registry = transition.successor;
        response_result(transition.response)
    }
}

impl ServerHandler for CompactCoordinationMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-compact-coordination", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor compact coordination session")
                    .with_description(
                        "Volatile content-addressed context-plus-checkpoint custody.",
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

fn response_result(response: CompactSessionResponse) -> CallToolResult {
    let is_error = response.is_error();
    let value = serde_json::to_value(&response).unwrap_or_else(|_| {
        json!({
            "profile": RESPONSE_PROFILE,
            "operation": "unavailable",
            "status": "internal_fault",
            "result": null,
            "fault": {"code": "response_encoding_failed", "message": "response serialization failed"},
            "nonclaims": []
        })
    });
    let content = vec![ContentBlock::text(format!(
        "Cantor compact session {} returned {}; use structuredContent as the complete machine response.",
        value["operation"].as_str().unwrap_or("unavailable"),
        value["status"].as_str().unwrap_or("internal_fault")
    ))];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(value);
    result
}

fn operation_hint(value: &Value) -> CompactSessionOperation {
    match value
        .get("request")
        .and_then(|request| request.get("operation"))
        .and_then(Value::as_str)
    {
        Some("open") => CompactSessionOperation::Open,
        Some("advance") => CompactSessionOperation::Advance,
        Some("inspect") => CompactSessionOperation::Inspect,
        Some("read") => CompactSessionOperation::Read,
        _ => CompactSessionOperation::Unavailable,
    }
}

fn schema_object<T: JsonSchema>() -> JsonObject {
    serde_json::to_value(schemars::schema_for!(T))
        .expect("generated schema must serialize")
        .as_object()
        .expect("generated schema root must be an object")
        .clone()
}
