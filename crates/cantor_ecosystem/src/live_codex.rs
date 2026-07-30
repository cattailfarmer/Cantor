//! Hash-pinned, read-only Codex App Server adapter.
//!
//! This module deliberately treats a live model turn as an untrusted transport
//! participant.  The app-server executable, Cantor MCP executable, runtime
//! environment, route, request, event set, tool count, response, and candidate
//! are all checked outside the model before the logical ecosystem cycle can
//! advance.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

use cantor_core::{
    ContentDigest, ProtocolRequest, ProtocolResponse, ProtocolStatus, SemanticId, sha256_bytes,
    sha256_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    CandidateArtifact, CantorAdapter, CodexAdapter, EcosystemFault, EcosystemFaultCode, WorkPacket,
};

pub const LIVE_CODEX_PROFILE: &str = "cantor-read-only-live-codex/0.1";
pub const LIVE_CODEX_CONFIG_PROFILE: &str = "cantor-live-codex-config/0.1";
pub const DEFAULT_MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_EVENTS: u32 = 4_096;
pub const DEFAULT_TIMEOUT_MILLIS: u64 = 300_000;
const HARD_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const HARD_MAX_EVENTS: u32 = 16_384;
const HARD_MAX_TIMEOUT_MILLIS: u64 = 900_000;
const MAX_STDERR_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveCodexConfig {
    pub profile: String,
    pub codex_executable: PathBuf,
    pub codex_executable_sha256: String,
    pub codex_version: String,
    pub cantor_mcp_executable: PathBuf,
    pub cantor_mcp_executable_sha256: String,
    pub environment_file: PathBuf,
    pub environment_file_sha256: String,
    pub working_directory: PathBuf,
    pub mcp_server_name: String,
    pub mcp_tool_name: String,
    pub timeout_millis: u64,
    pub max_line_bytes: usize,
    pub max_total_bytes: usize,
    pub max_events: u32,
}

impl LiveCodexConfig {
    pub fn validate(&self) -> Result<ValidatedLiveCodexConfig, EcosystemFault> {
        if self.profile != LIVE_CODEX_CONFIG_PROFILE {
            return live_fault("config", "unsupported live Codex profile");
        }
        if self.timeout_millis == 0 || self.timeout_millis > HARD_MAX_TIMEOUT_MILLIS {
            return live_fault("config", "timeout is zero or exceeds the hard limit");
        }
        if self.max_line_bytes == 0 || self.max_line_bytes > HARD_MAX_LINE_BYTES {
            return live_fault("config", "line limit is zero or exceeds the hard limit");
        }
        if self.max_total_bytes < self.max_line_bytes || self.max_total_bytes > HARD_MAX_TOTAL_BYTES
        {
            return live_fault("config", "total byte limit is invalid");
        }
        if self.max_events == 0 || self.max_events > HARD_MAX_EVENTS {
            return live_fault("config", "event limit is zero or exceeds the hard limit");
        }
        validate_route_component("MCP server", &self.mcp_server_name)?;
        validate_route_component("MCP tool", &self.mcp_tool_name)?;
        if self.mcp_tool_name != "query_sop" {
            return live_fault("config", "the stable Cantor tool must be query_sop");
        }

        let codex_executable = validate_regular_file(
            &self.codex_executable,
            &self.codex_executable_sha256,
            "Codex executable",
        )?;
        let cantor_mcp_executable = validate_regular_file(
            &self.cantor_mcp_executable,
            &self.cantor_mcp_executable_sha256,
            "Cantor MCP executable",
        )?;
        let environment_file = validate_regular_file(
            &self.environment_file,
            &self.environment_file_sha256,
            "Cantor environment",
        )?;
        let working_directory = validate_directory(&self.working_directory, "working directory")?;

        let version = bounded_command_version(&codex_executable)?;
        if version != self.codex_version {
            return live_fault(
                "config",
                format!(
                    "Codex version differs from the pin: expected {:?}, observed {:?}",
                    self.codex_version, version
                ),
            );
        }

        Ok(ValidatedLiveCodexConfig {
            source: self.clone(),
            codex_executable,
            cantor_mcp_executable,
            environment_file,
            working_directory,
        })
    }
}

impl Default for LiveCodexConfig {
    fn default() -> Self {
        Self {
            profile: LIVE_CODEX_CONFIG_PROFILE.to_owned(),
            codex_executable: PathBuf::new(),
            codex_executable_sha256: String::new(),
            codex_version: String::new(),
            cantor_mcp_executable: PathBuf::new(),
            cantor_mcp_executable_sha256: String::new(),
            environment_file: PathBuf::new(),
            environment_file_sha256: String::new(),
            working_directory: PathBuf::new(),
            mcp_server_name: "cantor".to_owned(),
            mcp_tool_name: "query_sop".to_owned(),
            timeout_millis: DEFAULT_TIMEOUT_MILLIS,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedLiveCodexConfig {
    source: LiveCodexConfig,
    codex_executable: PathBuf,
    cantor_mcp_executable: PathBuf,
    environment_file: PathBuf,
    working_directory: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveCandidatePayload {
    pub summary: String,
    pub satisfied_criterion_ids: BTreeSet<SemanticId>,
    pub proof_refs: BTreeSet<SemanticId>,
    pub requested_effects: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveTurnEvidence {
    pub profile: String,
    pub codex_executable_sha256: String,
    pub codex_version: String,
    pub cantor_mcp_executable_sha256: String,
    pub environment_file_sha256: String,
    pub thread_id: String,
    pub turn_id: String,
    pub event_count: u32,
    pub received_bytes: usize,
    pub mcp_call_id: String,
    pub mcp_server_name: String,
    pub mcp_tool_name: String,
    pub request_digest: ContentDigest,
    pub response_digest: ContentDigest,
    pub candidate_payload_digest: ContentDigest,
    pub advisories: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveTurnResult {
    pub request: ProtocolRequest,
    pub response: ProtocolResponse,
    pub candidate: LiveCandidatePayload,
    pub candidate_message: String,
    pub evidence: LiveTurnEvidence,
}

/// Testable boundary around one physical live turn.
pub trait LiveTurnDriver {
    fn run_turn(
        &mut self,
        work_packet: &WorkPacket,
        request: &ProtocolRequest,
        admitted_proof_refs: &BTreeSet<SemanticId>,
    ) -> Result<LiveTurnResult, EcosystemFault>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveAdapterState {
    New,
    TurnBuffered,
    ResponseReleased,
    CandidateReleased,
    Faulted,
}

#[derive(Clone, Debug)]
struct SharedExchange {
    state: LiveAdapterState,
    result: Option<LiveTurnResult>,
    cantor_calls: u32,
}

pub struct LiveCodexAdapter<Driver> {
    expected_work_packet_uuid: SemanticId,
    request: ProtocolRequest,
    admitted_proof_refs: BTreeSet<SemanticId>,
    driver: Driver,
    shared: Arc<Mutex<SharedExchange>>,
    calls: u32,
}

pub struct ObservedCantorAdapter {
    shared: Arc<Mutex<SharedExchange>>,
}

impl<Driver> LiveCodexAdapter<Driver> {
    pub fn new(
        expected_work_packet_uuid: SemanticId,
        request: ProtocolRequest,
        admitted_proof_refs: BTreeSet<SemanticId>,
        driver: Driver,
    ) -> (Self, ObservedCantorAdapter) {
        let shared = Arc::new(Mutex::new(SharedExchange {
            state: LiveAdapterState::New,
            result: None,
            cantor_calls: 0,
        }));
        (
            Self {
                expected_work_packet_uuid,
                request,
                admitted_proof_refs,
                driver,
                shared: Arc::clone(&shared),
                calls: 0,
            },
            ObservedCantorAdapter { shared },
        )
    }

    pub fn evidence(&self) -> Option<LiveTurnEvidence> {
        self.shared
            .lock()
            .ok()
            .and_then(|shared| shared.result.as_ref().map(|result| result.evidence.clone()))
    }

    fn fail(&mut self, message: impl AsRef<str>) -> EcosystemFault {
        if let Ok(mut shared) = self.shared.lock() {
            shared.state = LiveAdapterState::Faulted;
        }
        EcosystemFault::new(
            EcosystemFaultCode::AdapterFault,
            "live_codex",
            message,
            vec![self.expected_work_packet_uuid.clone()],
        )
    }
}

impl<Driver: LiveTurnDriver> CodexAdapter for LiveCodexAdapter<Driver> {
    fn accept_assignment(
        &mut self,
        work_packet: &WorkPacket,
    ) -> Result<ProtocolRequest, EcosystemFault> {
        self.calls = self.calls.saturating_add(1);
        if work_packet.work_packet_uuid != self.expected_work_packet_uuid {
            return Err(self.fail("assignment identity differs from the live binding"));
        }
        {
            let shared = self
                .shared
                .lock()
                .map_err(|_| live_error("live_codex", "shared exchange lock was poisoned"))?;
            if shared.state != LiveAdapterState::New {
                drop(shared);
                return Err(self.fail("assignment was delivered outside the new state"));
            }
        }
        let result = self
            .driver
            .run_turn(work_packet, &self.request, &self.admitted_proof_refs)?;
        if result.request != self.request {
            return Err(self.fail("live driver returned a different protocol request"));
        }
        cantor_core::verify_protocol_response(&self.request, &result.response).map_err(
            |fault| {
                self.fail(format!(
                    "live response failed verification: {}",
                    fault.message
                ))
            },
        )?;
        if result.response.status != ProtocolStatus::Success {
            return Err(self.fail("live Cantor response was not successful"));
        }
        let parsed_candidate = parse_candidate_json(&result.candidate_message, &self.request)
            .map_err(|fault| self.fail(fault.message))?;
        if parsed_candidate != result.candidate {
            return Err(self.fail("candidate payload differs from the observed final message"));
        }
        let request_digest =
            sha256_digest(&result.request).map_err(|fault| self.fail(fault.to_string()))?;
        let response_digest =
            sha256_digest(&result.response).map_err(|fault| self.fail(fault.to_string()))?;
        let candidate_message_digest = sha256_bytes(result.candidate_message.as_bytes());
        if result.evidence.request_digest != request_digest
            || result.evidence.response_digest != response_digest
            || result.evidence.candidate_payload_digest != candidate_message_digest
        {
            return Err(self.fail("live evidence digests do not bind the observed exchange"));
        }
        validate_candidate_payload(work_packet, &self.admitted_proof_refs, &result.candidate)
            .map_err(|fault| self.fail(fault.message))?;
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| live_error("live_codex", "shared exchange lock was poisoned"))?;
        shared.result = Some(result);
        shared.state = LiveAdapterState::TurnBuffered;
        Ok(self.request.clone())
    }

    fn accept_cantor_return(
        &mut self,
        request: &ProtocolRequest,
        response: &ProtocolResponse,
    ) -> Result<CandidateArtifact, EcosystemFault> {
        self.calls = self.calls.saturating_add(1);
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| live_error("live_codex", "shared exchange lock was poisoned"))?;
        if shared.state != LiveAdapterState::ResponseReleased {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::AdapterFault,
                "live_codex",
                "Cantor return was not released exactly once before candidate formation",
                vec![self.expected_work_packet_uuid.clone()],
            ));
        }
        let result = shared.result.as_ref().ok_or_else(|| {
            EcosystemFault::new(
                EcosystemFaultCode::AdapterFault,
                "live_codex",
                "buffered live result is absent",
                vec![self.expected_work_packet_uuid.clone()],
            )
        })?;
        if request != &result.request || response != &result.response {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::CorrelationMismatch,
                "live_codex",
                "logical Cantor return differs from the physically observed exchange",
                vec![request.request_id.clone()],
            ));
        }
        let payload = result.candidate.clone();
        let content_digest = result.evidence.candidate_payload_digest.clone();
        let candidate_uuid = SemanticId::new(format!(
            "{}:candidate:{}:sha256:{}",
            self.expected_work_packet_uuid, result.evidence.turn_id, content_digest.value
        ))
        .map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::InvalidIdentity,
                "live_codex",
                fault.to_string(),
                vec![self.expected_work_packet_uuid.clone()],
            )
        })?;
        let candidate = CandidateArtifact {
            candidate_uuid,
            content_digest,
            summary: payload.summary,
            satisfied_criterion_ids: payload.satisfied_criterion_ids,
            proof_refs: payload.proof_refs,
            requested_effects: payload.requested_effects,
        };
        candidate.validate()?;
        shared.state = LiveAdapterState::CandidateReleased;
        Ok(candidate)
    }

    fn call_count(&self) -> u32 {
        self.calls
    }
}

impl CantorAdapter for ObservedCantorAdapter {
    fn execute(&mut self, request: &ProtocolRequest) -> Result<ProtocolResponse, EcosystemFault> {
        let mut shared = self.shared.lock().map_err(|_| {
            EcosystemFault::new(
                EcosystemFaultCode::AdapterFault,
                "observed_cantor",
                "shared exchange lock was poisoned",
                vec![request.request_id.clone()],
            )
        })?;
        shared.cantor_calls = shared.cantor_calls.saturating_add(1);
        if shared.state != LiveAdapterState::TurnBuffered || shared.cantor_calls != 1 {
            shared.state = LiveAdapterState::Faulted;
            return live_fault(
                "observed_cantor",
                "the observed Cantor response may be released exactly once",
            );
        }
        let result = shared.result.as_ref().ok_or_else(|| {
            EcosystemFault::new(
                EcosystemFaultCode::AdapterFault,
                "observed_cantor",
                "buffered live result is absent",
                vec![request.request_id.clone()],
            )
        })?;
        if request != &result.request {
            shared.state = LiveAdapterState::Faulted;
            return live_fault(
                "observed_cantor",
                "logical query differs from the physically observed query",
            );
        }
        let response = result.response.clone();
        shared.state = LiveAdapterState::ResponseReleased;
        Ok(response)
    }

    fn call_count(&self) -> u32 {
        self.shared
            .lock()
            .map(|shared| shared.cantor_calls)
            .unwrap_or(u32::MAX)
    }
}

pub struct StdioAppServerDriver {
    config: ValidatedLiveCodexConfig,
}

impl StdioAppServerDriver {
    pub fn new(config: LiveCodexConfig) -> Result<Self, EcosystemFault> {
        Ok(Self {
            config: config.validate()?,
        })
    }
}

impl LiveTurnDriver for StdioAppServerDriver {
    fn run_turn(
        &mut self,
        work_packet: &WorkPacket,
        request: &ProtocolRequest,
        admitted_proof_refs: &BTreeSet<SemanticId>,
    ) -> Result<LiveTurnResult, EcosystemFault> {
        let mut transport = ChildTransport::spawn(&self.config)?;
        let result = run_app_server_session(
            &self.config,
            work_packet,
            request,
            admitted_proof_refs,
            &mut transport,
        );
        let finish = transport.finish();
        match (result, finish) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(fault), _) => Err(fault),
            (Ok(_), Err(fault)) => Err(fault),
        }
    }
}

trait AppServerTransport {
    fn send(&mut self, message: &Value) -> Result<(), EcosystemFault>;
    fn receive(&mut self, deadline: Instant) -> Result<Value, EcosystemFault>;
    fn received_bytes(&self) -> usize;
}

fn run_app_server_session<Transport: AppServerTransport>(
    config: &ValidatedLiveCodexConfig,
    work_packet: &WorkPacket,
    request: &ProtocolRequest,
    admitted_proof_refs: &BTreeSet<SemanticId>,
    transport: &mut Transport,
) -> Result<LiveTurnResult, EcosystemFault> {
    let deadline = Instant::now() + Duration::from_millis(config.source.timeout_millis);
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "clientInfo": {
                "name": "cantor-read-only-live-adapter",
                "title": "Cantor read-only live adapter",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": {
                "experimentalApi": false,
                "requestAttestation": false
            }
        }
    });
    transport.send(&initialize)?;
    let _initialize_result = expect_response(transport, deadline, 1)?;
    transport.send(&json!({"jsonrpc":"2.0","method":"initialized","params":{}}))?;

    transport.send(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "thread/start",
        "params": {
            "cwd": path_text(&config.working_directory)?,
            "approvalPolicy": "never",
            "sandbox": "read-only",
            "ephemeral": true,
            "personality": "none",
            "developerInstructions": format!(
                "This thread has exactly one permitted action: call MCP server {:?}, tool {:?}, \
                 exactly once with the supervisor-issued arguments. A final answer before that \
                 completed call is invalid. Do not use any other tool or effect surface.",
                config.source.mcp_server_name,
                config.source.mcp_tool_name
            )
        }
    }))?;
    let thread_result = expect_response(transport, deadline, 2)?;
    let thread_id = required_string(&thread_result, &["thread", "id"], "thread id")?;
    if thread_result.pointer("/thread/ephemeral") != Some(&Value::Bool(true)) {
        return live_fault(
            "app_server",
            "thread/start did not confirm an ephemeral thread",
        );
    }
    if thread_result.get("approvalPolicy").and_then(Value::as_str) != Some("never") {
        return live_fault(
            "app_server",
            "thread/start did not confirm approval policy never",
        );
    }
    if thread_result
        .pointer("/sandbox/type")
        .and_then(Value::as_str)
        != Some("readOnly")
        || thread_result
            .pointer("/sandbox/networkAccess")
            .is_some_and(|value| value != &Value::Bool(false))
    {
        return live_fault(
            "app_server",
            "thread/start did not confirm a read-only no-network sandbox",
        );
    }
    let returned_cwd = required_string(&thread_result, &["cwd"], "thread working directory")?;
    if fs::canonicalize(Path::new(&returned_cwd)).ok().as_ref() != Some(&config.working_directory) {
        return live_fault(
            "app_server",
            "thread/start returned a different working directory",
        );
    }

    let prompt = live_prompt(config, work_packet, request, admitted_proof_refs)?;
    transport.send(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "turn/start",
        "params": {
            "threadId": thread_id,
            "cwd": path_text(&config.working_directory)?,
            "approvalPolicy": "never",
            "sandboxPolicy": {"type":"readOnly","networkAccess":false},
            "input": [{"type":"text","text":prompt,"text_elements":[]}],
            "outputSchema": candidate_output_schema()
        }
    }))?;
    let turn_result = expect_response(transport, deadline, 3)?;
    let turn_id = required_string(&turn_result, &["turn", "id"], "turn id")?;
    if required_string(&turn_result, &["turn", "status"], "turn status")? != "inProgress" {
        return live_fault("app_server", "turn/start did not return inProgress");
    }

    let mut event_count = 0_u32;
    let mut started_mcp_id: Option<String> = None;
    let mut observed_call: Option<ObservedToolCall> = None;
    let mut final_message: Option<String> = None;
    let mut advisories = Vec::new();
    loop {
        let message = transport.receive(deadline)?;
        event_count = event_count.saturating_add(1);
        if event_count > config.source.max_events {
            return live_fault("app_server", "event budget exceeded");
        }
        reject_server_request(&message)?;
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return live_fault("app_server", "unexpected response after turn/start");
        };
        let params = message.get("params").ok_or_else(|| {
            EcosystemFault::new(
                EcosystemFaultCode::ProtocolFault,
                "app_server",
                "notification has no params",
                vec![request.request_id.clone()],
            )
        })?;
        match method {
            "item/completed" => {
                require_correlation(params, &thread_id, &turn_id)?;
                let item = params.get("item").ok_or_else(|| {
                    EcosystemFault::new(
                        EcosystemFaultCode::ProtocolFault,
                        "app_server",
                        "item/completed has no item",
                        vec![request.request_id.clone()],
                    )
                })?;
                let item_type = item.get("type").and_then(Value::as_str).unwrap_or("");
                match item_type {
                    "mcpToolCall" => {
                        if observed_call.is_some() {
                            return live_fault("app_server", "more than one MCP call completed");
                        }
                        let completed = parse_tool_call(config, request, item)?;
                        if started_mcp_id.as_deref() != Some(completed.call_id.as_str()) {
                            return live_fault(
                                "app_server",
                                "completed MCP call differs from the single started call",
                            );
                        }
                        observed_call = Some(completed);
                    }
                    "agentMessage" => {
                        let text = item.get("text").and_then(Value::as_str).ok_or_else(|| {
                            EcosystemFault::new(
                                EcosystemFaultCode::ProtocolFault,
                                "app_server",
                                "agent message has no text",
                                vec![request.request_id.clone()],
                            )
                        })?;
                        match item.get("phase").and_then(Value::as_str) {
                            Some("commentary") => {}
                            Some("final_answer") | None => {
                                if observed_call.is_none() {
                                    return live_fault(
                                        "app_server",
                                        format!(
                                            "final agent message completed before the required Cantor call: {:?}",
                                            text.chars().take(192).collect::<String>()
                                        ),
                                    );
                                }
                                if final_message.replace(text.to_owned()).is_some() {
                                    return live_fault(
                                        "app_server",
                                        "more than one final agent message followed the tool",
                                    );
                                }
                            }
                            Some(other) => {
                                return live_fault(
                                    "app_server",
                                    format!("unknown agent message phase {other:?}"),
                                );
                            }
                        }
                    }
                    "userMessage" | "reasoning" | "plan" => {}
                    forbidden => {
                        return live_fault(
                            "app_server",
                            format!("forbidden completed item type: {forbidden:?}"),
                        );
                    }
                }
            }
            "turn/completed" => {
                require_terminal_correlation(params, &thread_id, &turn_id)?;
                let status = required_string(params, &["turn", "status"], "terminal status")?;
                if status != "completed" {
                    return live_fault(
                        "app_server",
                        format!("turn ended with non-completed status {status:?}"),
                    );
                }
                break;
            }
            // Passive progress notifications are not authority. Completed items
            // and the terminal turn remain the authoritative surface.
            "item/started" => {
                require_correlation(params, &thread_id, &turn_id)?;
                let item = params
                    .get("item")
                    .ok_or_else(|| live_error("app_server", "item/started has no item"))?;
                let item_type = item.get("type").and_then(Value::as_str).unwrap_or("");
                match item_type {
                    "mcpToolCall" => {
                        if started_mcp_id.is_some() {
                            return live_fault("app_server", "more than one MCP call started");
                        }
                        started_mcp_id = Some(validate_started_tool_call(config, request, item)?);
                    }
                    "userMessage" | "reasoning" | "plan" | "agentMessage" => {}
                    forbidden => {
                        return live_fault(
                            "app_server",
                            format!("forbidden started item type: {forbidden:?}"),
                        );
                    }
                }
            }
            "thread/started"
            | "turn/started"
            | "item/agentMessage/delta"
            | "item/mcpToolCall/progress"
            | "item/plan/delta"
            | "item/reasoning/summaryPartAdded"
            | "item/reasoning/summaryTextDelta"
            | "item/reasoning/textDelta"
            | "mcpServer/startupStatus/updated"
            | "model/verification"
            | "remoteControl/status/changed"
            | "thread/status/changed"
            | "thread/tokenUsage/updated"
            | "turn/plan/updated"
            | "account/rateLimits/updated" => {}
            "warning"
            | "configWarning"
            | "deprecationNotice"
            | "guardianWarning"
            | "windows/worldWritableWarning" => {
                if advisories.len() >= 32 {
                    return live_fault("app_server", "advisory notification budget exceeded");
                }
                advisories.push(format!("{method}: {}", bounded_json(params)));
            }
            "error" => {
                return live_fault(
                    "app_server",
                    format!("app-server error notification: {}", bounded_json(params)),
                );
            }
            forbidden => {
                return live_fault(
                    "app_server",
                    format!("unrecognized or forbidden notification: {forbidden:?}"),
                );
            }
        }
    }

    let observed_call =
        observed_call.ok_or_else(|| live_error("app_server", "required Cantor call is absent"))?;
    let final_message = final_message
        .ok_or_else(|| live_error("app_server", "final candidate message is absent"))?;
    let candidate = parse_candidate_json(&final_message, request)?;
    validate_candidate_payload(work_packet, admitted_proof_refs, &candidate)?;
    let request_digest = sha256_digest(request).map_err(serialization_fault)?;
    let response_digest = sha256_digest(&observed_call.response).map_err(serialization_fault)?;
    let candidate_payload_digest = sha256_bytes(final_message.as_bytes());
    Ok(LiveTurnResult {
        request: request.clone(),
        response: observed_call.response,
        candidate,
        candidate_message: final_message,
        evidence: LiveTurnEvidence {
            profile: LIVE_CODEX_PROFILE.to_owned(),
            codex_executable_sha256: config.source.codex_executable_sha256.clone(),
            codex_version: config.source.codex_version.clone(),
            cantor_mcp_executable_sha256: config.source.cantor_mcp_executable_sha256.clone(),
            environment_file_sha256: config.source.environment_file_sha256.clone(),
            thread_id,
            turn_id,
            event_count,
            received_bytes: transport.received_bytes(),
            mcp_call_id: observed_call.call_id,
            mcp_server_name: config.source.mcp_server_name.clone(),
            mcp_tool_name: config.source.mcp_tool_name.clone(),
            request_digest,
            response_digest,
            candidate_payload_digest,
            advisories,
        },
    })
}

#[derive(Debug)]
struct ObservedToolCall {
    call_id: String,
    response: ProtocolResponse,
}

fn parse_tool_call(
    config: &ValidatedLiveCodexConfig,
    request: &ProtocolRequest,
    item: &Value,
) -> Result<ObservedToolCall, EcosystemFault> {
    if item.get("server").and_then(Value::as_str) != Some(config.source.mcp_server_name.as_str())
        || item.get("tool").and_then(Value::as_str) != Some(config.source.mcp_tool_name.as_str())
    {
        return live_fault("app_server", "MCP call used an unapproved route");
    }
    if item.get("status").and_then(Value::as_str) != Some("completed")
        || !item.get("error").is_none_or(Value::is_null)
    {
        return live_fault(
            "app_server",
            "Cantor MCP call did not complete successfully",
        );
    }
    let arguments = item
        .get("arguments")
        .ok_or_else(|| live_error("app_server", "Cantor MCP call omitted arguments"))?;
    let expected_arguments = json!({"request": request});
    if arguments != &expected_arguments {
        return live_fault(
            "app_server",
            "Cantor MCP arguments differ from the supervisor-issued request",
        );
    }
    let structured = item
        .pointer("/result/structuredContent")
        .ok_or_else(|| live_error("app_server", "Cantor MCP result omitted structuredContent"))?;
    let response: ProtocolResponse =
        serde_json::from_value(structured.clone()).map_err(|error| {
            EcosystemFault::new(
                EcosystemFaultCode::SerializationFault,
                "app_server",
                format!("Cantor structuredContent is not a ProtocolResponse: {error}"),
                vec![request.request_id.clone()],
            )
        })?;
    cantor_core::verify_protocol_response(request, &response).map_err(|fault| {
        EcosystemFault::new(
            EcosystemFaultCode::ProtocolFault,
            "app_server",
            fault.message,
            vec![request.request_id.clone()],
        )
    })?;
    let call_id = item
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| live_error("app_server", "Cantor MCP call id is absent"))?
        .to_owned();
    Ok(ObservedToolCall { call_id, response })
}

fn validate_started_tool_call(
    config: &ValidatedLiveCodexConfig,
    request: &ProtocolRequest,
    item: &Value,
) -> Result<String, EcosystemFault> {
    if item.get("server").and_then(Value::as_str) != Some(config.source.mcp_server_name.as_str())
        || item.get("tool").and_then(Value::as_str) != Some(config.source.mcp_tool_name.as_str())
    {
        return live_fault("app_server", "started MCP call used an unapproved route");
    }
    if item.get("arguments") != Some(&json!({"request": request})) {
        return live_fault(
            "app_server",
            "started Cantor MCP arguments differ from the supervisor-issued request",
        );
    }
    item.get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| live_error("app_server", "started Cantor MCP call id is absent"))
}

fn expect_response<Transport: AppServerTransport>(
    transport: &mut Transport,
    deadline: Instant,
    expected_id: u64,
) -> Result<Value, EcosystemFault> {
    loop {
        let message = transport.receive(deadline)?;
        reject_server_request(&message)?;
        if let Some(id) = message.get("id") {
            if id.as_u64() != Some(expected_id) {
                return live_fault("app_server", "response id differs from the request id");
            }
            if let Some(error) = message.get("error") {
                return live_fault(
                    "app_server",
                    format!("app-server request failed: {}", bounded_json(error)),
                );
            }
            return message
                .get("result")
                .cloned()
                .ok_or_else(|| live_error("app_server", "response has no result"));
        }
        // Startup notifications are informative but cannot substitute for the
        // exact correlated response. Keep this allowlist narrow so a new
        // interactive request or actionable event cannot disappear in setup.
        match message.get("method").and_then(Value::as_str) {
            Some(
                "mcpServer/startupStatus/updated"
                | "remoteControl/status/changed"
                | "thread/started"
                | "thread/status/changed"
                | "account/rateLimits/updated"
                | "warning"
                | "configWarning"
                | "deprecationNotice",
            ) => {}
            Some("error") => {
                return live_fault(
                    "app_server",
                    format!(
                        "app-server error before response: {}",
                        bounded_json(message.get("params").unwrap_or(&Value::Null))
                    ),
                );
            }
            Some(other) => {
                return live_fault(
                    "app_server",
                    format!("notification {other:?} is not admitted before response"),
                );
            }
            None => {
                return live_fault("app_server", "invalid JSON-RPC message before response");
            }
        }
    }
}

fn reject_server_request(message: &Value) -> Result<(), EcosystemFault> {
    if message.get("method").is_some() && message.get("id").is_some() {
        return live_fault(
            "app_server",
            "server request is forbidden in the non-interactive live profile",
        );
    }
    Ok(())
}

fn require_correlation(
    params: &Value,
    thread_id: &str,
    turn_id: &str,
) -> Result<(), EcosystemFault> {
    if params.get("threadId").and_then(Value::as_str) != Some(thread_id)
        || params.get("turnId").and_then(Value::as_str) != Some(turn_id)
    {
        return live_fault(
            "app_server",
            "notification correlation differs from the live turn",
        );
    }
    Ok(())
}

fn require_terminal_correlation(
    params: &Value,
    thread_id: &str,
    turn_id: &str,
) -> Result<(), EcosystemFault> {
    if params.get("threadId").and_then(Value::as_str) != Some(thread_id)
        || params.pointer("/turn/id").and_then(Value::as_str) != Some(turn_id)
    {
        return live_fault(
            "app_server",
            "terminal notification correlation differs from the live turn",
        );
    }
    Ok(())
}

fn live_prompt(
    config: &ValidatedLiveCodexConfig,
    work_packet: &WorkPacket,
    request: &ProtocolRequest,
    admitted_proof_refs: &BTreeSet<SemanticId>,
) -> Result<String, EcosystemFault> {
    let request_json = serde_json::to_string(request).map_err(serialization_fault)?;
    let criteria_json =
        serde_json::to_string(&work_packet.acceptance_criteria).map_err(serialization_fault)?;
    let proof_refs_json =
        serde_json::to_string(admitted_proof_refs).map_err(serialization_fault)?;
    Ok(format!(
        "You are the single read-only Codex worker inside {LIVE_CODEX_PROFILE}.\n\
         Subject: {subject}\nPurpose: {purpose}\nRequested result: {result}\n\
         Acceptance criteria JSON: {criteria}\n\
         You MUST call MCP server {server:?}, tool {tool:?}, exactly once. Pass exactly this JSON \
         object as the tool arguments, byte meaning preserved: {{\"request\":{request}}}\n\
         Do not call any other tool, command, file operation, web operation, sub-agent, user-input \
         request, permission request, or approval. Do not retry, steer, or persist anything.\n\
         Treat structuredContent as the authoritative ProtocolResponse. After that successful call, \
         return only one JSON object matching the supplied output schema. Its \
         satisfied_criterion_ids may contain only the listed criterion IDs and must include every \
         criterion actually satisfied. proof_refs MUST equal this supervisor-admitted JSON set \
         exactly: {proof_refs}. requested_effects MUST be empty. Do not place prose outside \
         the JSON object.",
        subject = work_packet.subject,
        purpose = work_packet.purpose,
        result = work_packet.requested_result,
        criteria = criteria_json,
        proof_refs = proof_refs_json,
        server = config.source.mcp_server_name,
        tool = config.source.mcp_tool_name,
        request = request_json,
    ))
}

fn candidate_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "summary",
            "satisfied_criterion_ids",
            "proof_refs",
            "requested_effects"
        ],
        "properties": {
            "summary": {"type":"string","minLength":1,"maxLength":16384},
            "satisfied_criterion_ids": {
                "type":"array","maxItems":256,"items":{"type":"string"}
            },
            "proof_refs": {
                "type":"array","maxItems":256,"items":{"type":"string"}
            },
            "requested_effects": {
                "type":"array","maxItems":0,"items":{"type":"string"}
            }
        }
    })
}

fn parse_candidate_json(
    text: &str,
    request: &ProtocolRequest,
) -> Result<LiveCandidatePayload, EcosystemFault> {
    let value: Value = serde_json::from_str(text).map_err(|error| {
        EcosystemFault::new(
            EcosystemFaultCode::SerializationFault,
            "app_server",
            format!("candidate JSON is invalid: {error}"),
            vec![request.request_id.clone()],
        )
    })?;
    for field in ["satisfied_criterion_ids", "proof_refs", "requested_effects"] {
        let values = value.get(field).and_then(Value::as_array).ok_or_else(|| {
            EcosystemFault::new(
                EcosystemFaultCode::SerializationFault,
                "app_server",
                format!("candidate field {field:?} is not an array"),
                vec![request.request_id.clone()],
            )
        })?;
        let mut unique = BTreeSet::new();
        for entry in values {
            let entry = entry.as_str().ok_or_else(|| {
                EcosystemFault::new(
                    EcosystemFaultCode::SerializationFault,
                    "app_server",
                    format!("candidate field {field:?} contains a non-string"),
                    vec![request.request_id.clone()],
                )
            })?;
            if !unique.insert(entry) {
                return live_fault(
                    "app_server",
                    format!("candidate field {field:?} contains a duplicate"),
                );
            }
        }
    }
    serde_json::from_value(value).map_err(|error| {
        EcosystemFault::new(
            EcosystemFaultCode::SerializationFault,
            "app_server",
            format!("candidate JSON has the wrong strict form: {error}"),
            vec![request.request_id.clone()],
        )
    })
}

fn validate_candidate_payload(
    work_packet: &WorkPacket,
    admitted_proof_refs: &BTreeSet<SemanticId>,
    candidate: &LiveCandidatePayload,
) -> Result<(), EcosystemFault> {
    if candidate.summary.trim().is_empty() || candidate.summary.len() > 16_384 {
        return live_fault("live_candidate", "candidate summary is empty or oversized");
    }
    if !candidate.requested_effects.is_empty() {
        return live_fault(
            "live_candidate",
            "live candidate requested a forbidden effect",
        );
    }
    let known = work_packet.criterion_ids();
    if !candidate
        .satisfied_criterion_ids
        .iter()
        .all(|criterion| known.contains(criterion))
    {
        return live_fault("live_candidate", "candidate claims an unknown criterion");
    }
    if !known.is_subset(&candidate.satisfied_criterion_ids) {
        return live_fault("live_candidate", "candidate omits an acceptance criterion");
    }
    if &candidate.proof_refs != admitted_proof_refs {
        return live_fault(
            "live_candidate",
            "candidate proof references differ from the supervisor-admitted set",
        );
    }
    Ok(())
}

struct ChildTransport {
    child: Child,
    stdin: Option<ChildStdin>,
    receiver: Receiver<ReaderEvent>,
    reader: Option<thread::JoinHandle<()>>,
    stderr_reader: Option<thread::JoinHandle<Vec<u8>>>,
    max_total_bytes: usize,
    received_bytes: usize,
}

enum ReaderEvent {
    Line(Vec<u8>),
    Fault(String),
    Eof,
}

impl ChildTransport {
    fn spawn(config: &ValidatedLiveCodexConfig) -> Result<Self, EcosystemFault> {
        let server_name = toml_key(&config.source.mcp_server_name)?;
        let mcp_path = toml_string(&path_text(&config.cantor_mcp_executable)?)?;
        let environment_path = toml_string(&path_text(&config.environment_file)?)?;
        let mut command = Command::new(&config.codex_executable);
        command
            .arg("app-server")
            .arg("--listen")
            .arg("stdio://")
            .arg("-c")
            .arg("mcp_servers={}")
            .arg("-c")
            .arg(format!("mcp_servers.{server_name}.command={mcp_path}"))
            .arg("-c")
            .arg(format!(
                "mcp_servers.{server_name}.args=['--environment',{environment_path}]"
            ))
            .arg("-c")
            .arg(format!("mcp_servers.{server_name}.required=true"))
            .current_dir(&config.working_directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            live_error(
                "app_server_spawn",
                format!("could not launch pinned Codex executable: {error}"),
            )
        })?;
        let Some(stdin) = child.stdin.take() else {
            terminate_child(&mut child);
            return live_fault("app_server_spawn", "child stdin is unavailable");
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            return live_fault("app_server_spawn", "child stdout is unavailable");
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_child(&mut child);
            return live_fault("app_server_spawn", "child stderr is unavailable");
        };
        // A synchronous two-line queue keeps the reader concurrent without
        // allowing the producer to outpace the configured total-byte gate.
        let (sender, receiver) = mpsc::sync_channel(2);
        let max_line_bytes = config.source.max_line_bytes;
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let mut bounded = Read::take(&mut reader, (max_line_bytes + 1) as u64);
                match bounded.read_until(b'\n', &mut line) {
                    Ok(0) => {
                        let _ = sender.send(ReaderEvent::Eof);
                        break;
                    }
                    Ok(_) if line.len() > max_line_bytes => {
                        let _ = sender.send(ReaderEvent::Fault(
                            "app-server JSONL line exceeded the configured limit".to_owned(),
                        ));
                        break;
                    }
                    Ok(_) => {
                        if sender.send(ReaderEvent::Line(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(ReaderEvent::Fault(format!(
                            "app-server stdout read failed: {error}"
                        )));
                        break;
                    }
                }
            }
        });
        let stderr_reader = thread::spawn(move || {
            let mut stderr = stderr;
            let mut retained = Vec::new();
            let mut buffer = [0_u8; 8 * 1024];
            loop {
                match stderr.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        let remaining = MAX_STDERR_BYTES.saturating_sub(retained.len());
                        retained.extend_from_slice(&buffer[..count.min(remaining)]);
                    }
                }
            }
            retained
        });
        Ok(Self {
            child,
            stdin: Some(stdin),
            receiver,
            reader: Some(reader),
            stderr_reader: Some(stderr_reader),
            max_total_bytes: config.source.max_total_bytes,
            received_bytes: 0,
        })
    }

    fn finish(&mut self) -> Result<(), EcosystemFault> {
        self.stdin.take();
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        let (terminal_status, forced_termination) = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    break (Some(status), false);
                }
                Ok(None) if Instant::now() < wait_deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    self.child
                        .kill()
                        .map_err(|error| live_error("app_server_finish", error.to_string()))?;
                    break (self.child.wait().ok(), true);
                }
                Err(error) => return live_fault("app_server_finish", error.to_string()),
            }
        };
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
        if forced_termination {
            live_fault(
                "app_server_finish",
                "app-server required forced termination after terminal completion",
            )
        } else if terminal_status.is_some_and(|status| !status.success()) {
            live_fault(
                "app_server_finish",
                "app-server exited unsuccessfully after terminal completion",
            )
        } else {
            Ok(())
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for ChildTransport {
    fn drop(&mut self) {
        self.stdin.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

impl AppServerTransport for ChildTransport {
    fn send(&mut self, message: &Value) -> Result<(), EcosystemFault> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| live_error("app_server", "child stdin is closed"))?;
        serde_json::to_writer(&mut *stdin, message).map_err(serialization_fault)?;
        stdin
            .write_all(b"\n")
            .and_then(|()| stdin.flush())
            .map_err(|error| live_error("app_server", format!("stdin write failed: {error}")))
    }

    fn receive(&mut self, deadline: Instant) -> Result<Value, EcosystemFault> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| live_error("app_server", "live turn deadline expired"))?;
        match self.receiver.recv_timeout(remaining) {
            Ok(ReaderEvent::Line(line)) => {
                self.received_bytes = self.received_bytes.saturating_add(line.len());
                if self.received_bytes > self.max_total_bytes {
                    return live_fault("app_server", "JSONL byte budget exceeded");
                }
                serde_json::from_slice(&line).map_err(|error| {
                    live_error("app_server", format!("invalid JSONL message: {error}"))
                })
            }
            Ok(ReaderEvent::Fault(message)) => live_fault("app_server", message),
            Ok(ReaderEvent::Eof) => live_fault("app_server", "app-server stdout closed early"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                live_fault("app_server", "live turn deadline expired")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                live_fault("app_server", "app-server reader disconnected")
            }
        }
    }

    fn received_bytes(&self) -> usize {
        self.received_bytes
    }
}

fn validate_regular_file(
    path: &Path,
    expected_sha256: &str,
    label: &str,
) -> Result<PathBuf, EcosystemFault> {
    validate_sha256_text(expected_sha256, label)?;
    if !path.is_absolute() {
        return live_fault("config", format!("{label} path is not absolute"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| live_error("config", format!("{label} metadata failed: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return live_fault(
            "config",
            format!("{label} is not a non-symlink regular file"),
        );
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        live_error(
            "config",
            format!("{label} canonicalization failed: {error}"),
        )
    })?;
    let observed = hash_file(&canonical)?;
    if !observed.eq_ignore_ascii_case(expected_sha256) {
        return live_fault(
            "config",
            format!("{label} SHA-256 differs from the compile-time/operator pin"),
        );
    }
    Ok(canonical)
}

fn validate_directory(path: &Path, label: &str) -> Result<PathBuf, EcosystemFault> {
    if !path.is_absolute() {
        return live_fault("config", format!("{label} path is not absolute"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| live_error("config", format!("{label} metadata failed: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return live_fault("config", format!("{label} is not a non-symlink directory"));
    }
    fs::canonicalize(path).map_err(|error| {
        live_error(
            "config",
            format!("{label} canonicalization failed: {error}"),
        )
    })
}

pub fn sha256_file(path: &Path) -> Result<String, EcosystemFault> {
    hash_file(path)
}

fn hash_file(path: &Path) -> Result<String, EcosystemFault> {
    let mut file = File::open(path)
        .map_err(|error| live_error("config", format!("file hash open failed: {error}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| live_error("config", format!("file hash read failed: {error}")))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn bounded_command_version(path: &Path) -> Result<String, EcosystemFault> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| live_error("config", format!("Codex version probe failed: {error}")))?;
    if !output.status.success() || output.stdout.len() > 4_096 || output.stderr.len() > 4_096 {
        return live_fault("config", "Codex version probe failed or exceeded its bound");
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| live_error("config", "Codex version output is not UTF-8"))?
        .trim()
        .to_owned();
    if value.is_empty() {
        return live_fault("config", "Codex version output is empty");
    }
    Ok(value)
}

fn validate_sha256_text(value: &str, label: &str) -> Result<(), EcosystemFault> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return live_fault("config", format!("{label} SHA-256 pin is malformed"));
    }
    Ok(())
}

fn validate_route_component(label: &str, value: &str) -> Result<(), EcosystemFault> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return live_fault("config", format!("{label} name is invalid"));
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, EcosystemFault> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| live_error("config", "path is not representable as UTF-8"))
}

fn toml_key(value: &str) -> Result<String, EcosystemFault> {
    validate_route_component("TOML key", value)?;
    Ok(value.to_owned())
}

fn toml_string(value: &str) -> Result<String, EcosystemFault> {
    let encoded = serde_json::to_string(value).map_err(serialization_fault)?;
    Ok(encoded)
}

fn required_string(value: &Value, path: &[&str], label: &str) -> Result<String, EcosystemFault> {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .ok_or_else(|| live_error("app_server", format!("{label} is absent")))?;
    }
    current
        .as_str()
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| live_error("app_server", format!("{label} is not a non-empty string")))
}

fn bounded_json(value: &Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "<unencodable>".to_owned())
        .chars()
        .take(2_048)
        .collect()
}

fn serialization_fault(error: impl ToString) -> EcosystemFault {
    EcosystemFault::new(
        EcosystemFaultCode::SerializationFault,
        "live_codex",
        error.to_string(),
        Vec::new(),
    )
}

fn live_error(stage: &str, message: impl AsRef<str>) -> EcosystemFault {
    EcosystemFault::new(EcosystemFaultCode::AdapterFault, stage, message, Vec::new())
}

fn live_fault<T>(stage: &str, message: impl AsRef<str>) -> Result<T, EcosystemFault> {
    Err(live_error(stage, message))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};

    use cantor_core::{
        AuthorityScope, ExitClass, FabricMetrics, InspectRequest, InspectResult, PROTOCOL_VERSION,
        ProtocolCallerContext, ProtocolContinuation, ProtocolOperation, ProtocolOutcome,
        ProtocolProof, sha256_bytes,
    };

    use super::*;
    use crate::{
        AcceptanceCriterion, AuthorityGrant, EcosystemBudget, ParticipantAddress, ParticipantRole,
        WORK_PACKET_PROFILE,
    };

    struct ScriptedTransport {
        incoming: VecDeque<Value>,
        sent: Vec<Value>,
        received_bytes: usize,
    }

    impl AppServerTransport for ScriptedTransport {
        fn send(&mut self, message: &Value) -> Result<(), EcosystemFault> {
            self.sent.push(message.clone());
            Ok(())
        }

        fn receive(&mut self, _deadline: Instant) -> Result<Value, EcosystemFault> {
            let message = self
                .incoming
                .pop_front()
                .ok_or_else(|| live_error("script", "script exhausted"))?;
            self.received_bytes = self
                .received_bytes
                .saturating_add(serde_json::to_vec(&message).expect("script JSON").len() + 1);
            Ok(message)
        }

        fn received_bytes(&self) -> usize {
            self.received_bytes
        }
    }

    fn id(value: &str) -> SemanticId {
        SemanticId::new(value).expect("test identity")
    }

    fn protocol_exchange() -> (ProtocolRequest, ProtocolResponse) {
        let environment_digest = sha256_bytes(b"live-test-environment");
        let request = ProtocolRequest {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            request_id: id("request:live_parser"),
            caller_context: ProtocolCallerContext {
                caller_id: id("codex:live_parser"),
                purpose: "test the strict app-server parser".to_owned(),
                job_id: Some(id("work:live_parser")),
                effect_boundary: "read_only".to_owned(),
            },
            expected_environment_digest: environment_digest.clone(),
            expected_packages: Vec::new(),
            requested_scope: AuthorityScope {
                projects: BTreeSet::new(),
                namespaces: BTreeSet::new(),
                semantic_kinds: BTreeSet::new(),
                perspectives: BTreeSet::new(),
                instruction_capabilities: BTreeSet::new(),
            },
            request: ProtocolOperation::Inspect {
                inspect: InspectRequest::Fabric,
            },
        };
        let inspect = InspectResult::Fabric {
            metrics: FabricMetrics {
                package_count: 0,
                semantic_unit_count: 0,
                relation_count: 0,
                signed_source_bytes: 0,
                serialized_package_bytes: 0,
            },
            package_ids: Vec::new(),
        };
        let response = ProtocolResponse {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            request_id: request.request_id.clone(),
            operation: "inspect".to_owned(),
            status: ProtocolStatus::Success,
            exit_class: ExitClass::Success,
            result: ProtocolOutcome::Inspect(inspect.clone()),
            faults: Vec::new(),
            proof: ProtocolProof {
                admitted_package_ids: Vec::new(),
                expected_package_set_verified: true,
                environment_digest: Some(environment_digest),
                core_result_digest: Some(sha256_digest(&inspect).expect("result digest")),
            },
            continuation: ProtocolContinuation::Finish,
        };
        cantor_core::verify_protocol_response(&request, &response).expect("test protocol");
        (request, response)
    }

    fn packet() -> WorkPacket {
        WorkPacket {
            profile: WORK_PACKET_PROFILE.to_owned(),
            work_packet_uuid: id("work:live_parser"),
            commission_uuid: id("commission:live_parser"),
            worker: ParticipantAddress::new(ParticipantRole::CodexThread, "codex:live_parser")
                .expect("worker"),
            cantor_participant: ParticipantAddress::new(
                ParticipantRole::CantorParticipant,
                "cantor:live_parser",
            )
            .expect("Cantor"),
            observer: ParticipantAddress::new(ParticipantRole::Observer, "observer:live_parser")
                .expect("Observer"),
            subject: "strict live parser".to_owned(),
            purpose: "prove exact event admission".to_owned(),
            requested_result: "one bounded candidate".to_owned(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: id("criterion:live_parser"),
                description: "strict transcript accepted".to_owned(),
            }],
            authority_grant: AuthorityGrant::default(),
            frame_digest: sha256_bytes(b"live-parser-frame"),
            budget: EcosystemBudget {
                maximum_messages: 16,
                maximum_serialized_bytes: 1_000_000,
                maximum_call_depth: 4,
                maximum_logical_ticks: 32,
            },
        }
    }

    fn config() -> ValidatedLiveCodexConfig {
        let source = LiveCodexConfig {
            profile: LIVE_CODEX_CONFIG_PROFILE.to_owned(),
            codex_executable: PathBuf::from("codex"),
            codex_executable_sha256: "11".repeat(32),
            codex_version: "codex-cli test".to_owned(),
            cantor_mcp_executable: PathBuf::from("cantor-mcp"),
            cantor_mcp_executable_sha256: "22".repeat(32),
            environment_file: PathBuf::from("environment.json"),
            environment_file_sha256: "33".repeat(32),
            working_directory: PathBuf::from("."),
            mcp_server_name: "cantor".to_owned(),
            mcp_tool_name: "query_sop".to_owned(),
            timeout_millis: 10_000,
            max_line_bytes: 1_000_000,
            max_total_bytes: 4_000_000,
            max_events: 32,
        };
        ValidatedLiveCodexConfig {
            source,
            codex_executable: PathBuf::from("codex"),
            cantor_mcp_executable: PathBuf::from("cantor-mcp"),
            environment_file: PathBuf::from("environment.json"),
            working_directory: fs::canonicalize(
                std::env::current_dir().expect("test working directory"),
            )
            .expect("canonical test working directory"),
        }
    }

    fn successful_script(request: &ProtocolRequest, response: &ProtocolResponse) -> Vec<Value> {
        let cwd = path_text(&config().working_directory).expect("test cwd");
        let payload = LiveCandidatePayload {
            summary: "strict transcript accepted".to_owned(),
            satisfied_criterion_ids: [id("criterion:live_parser")].into_iter().collect(),
            proof_refs: BTreeSet::new(),
            requested_effects: BTreeSet::new(),
        };
        let arguments = json!({"request":request});
        vec![
            json!({"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"codex"}}}),
            json!({"jsonrpc":"2.0","id":2,"result":{
                "approvalPolicy":"never",
                "sandbox":{"type":"readOnly","networkAccess":false},
                "cwd":cwd,
                "thread":{"id":"thread-live","ephemeral":true}
            }}),
            json!({"jsonrpc":"2.0","id":3,"result":{
                "turn":{"id":"turn-live","status":"inProgress","items":[]}
            }}),
            json!({"jsonrpc":"2.0","method":"item/started","params":{
                "threadId":"thread-live","turnId":"turn-live",
                "item":{"type":"mcpToolCall","id":"call-live","server":"cantor",
                        "tool":"query_sop","arguments":arguments,"status":"inProgress"}
            }}),
            json!({"jsonrpc":"2.0","method":"item/completed","params":{
                "threadId":"thread-live","turnId":"turn-live","completedAtMs":1,
                "item":{"type":"mcpToolCall","id":"call-live","server":"cantor",
                        "tool":"query_sop","arguments":{"request":request},"status":"completed",
                        "error":null,"result":{"content":[],"structuredContent":response}}
            }}),
            json!({"jsonrpc":"2.0","method":"item/completed","params":{
                "threadId":"thread-live","turnId":"turn-live","completedAtMs":2,
                "item":{"type":"agentMessage","id":"message-live","phase":"final_answer",
                        "text":serde_json::to_string(&payload).expect("payload")}
            }}),
            json!({"jsonrpc":"2.0","method":"turn/completed","params":{
                "threadId":"thread-live",
                "turn":{"id":"turn-live","status":"completed","items":[]}
            }}),
        ]
    }

    fn run_script(messages: Vec<Value>) -> Result<LiveTurnResult, EcosystemFault> {
        let (request, _) = protocol_exchange();
        let mut transport = ScriptedTransport {
            incoming: messages.into(),
            sent: Vec::new(),
            received_bytes: 0,
        };
        let result = run_app_server_session(
            &config(),
            &packet(),
            &request,
            &BTreeSet::new(),
            &mut transport,
        )?;
        assert_eq!(transport.sent.len(), 4);
        assert_eq!(transport.sent[0]["method"], "initialize");
        assert_eq!(transport.sent[1]["method"], "initialized");
        assert_eq!(transport.sent[2]["method"], "thread/start");
        assert_eq!(transport.sent[3]["method"], "turn/start");
        assert_eq!(
            transport.sent[3].pointer("/params/approvalPolicy"),
            Some(&Value::String("never".to_owned()))
        );
        assert_eq!(
            transport.sent[3].pointer("/params/sandboxPolicy"),
            Some(&json!({"type":"readOnly","networkAccess":false}))
        );
        Ok(result)
    }

    #[test]
    fn strict_session_accepts_one_exact_read_only_cantor_exchange() {
        let (request, response) = protocol_exchange();
        let result =
            run_script(successful_script(&request, &response)).expect("strict live session");
        assert_eq!(result.request, request);
        assert_eq!(result.response, response);
        assert_eq!(result.evidence.event_count, 4);
        assert_eq!(result.evidence.mcp_call_id, "call-live");
    }

    #[test]
    fn strict_session_rejects_wrong_tool_route_at_start() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[3]["params"]["item"]["server"] = json!("other");
        let fault = run_script(script).expect_err("wrong route");
        assert!(fault.message.contains("unapproved route"));
    }

    #[test]
    fn strict_session_rejects_argument_substitution_at_start() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[3]["params"]["item"]["arguments"] = json!({"request":{"substituted":true}});
        let fault = run_script(script).expect_err("argument substitution");
        assert!(fault.message.contains("differ"));
    }

    #[test]
    fn strict_session_rejects_forbidden_command_before_completion() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[3]["params"]["item"] = json!({"type":"commandExecution","id":"command-live","status":"inProgress",
                   "command":"whoami"});
        let fault = run_script(script).expect_err("command must be forbidden");
        assert!(fault.message.contains("forbidden started item"));
    }

    #[test]
    fn strict_session_rejects_server_requests() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[3] = json!({"jsonrpc":"2.0","id":55,"method":"item/tool/call","params":{}});
        let fault = run_script(script).expect_err("server request");
        assert!(fault.message.contains("server request"));
    }

    #[test]
    fn strict_session_rejects_duplicate_mcp_start() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script.insert(4, script[3].clone());
        let fault = run_script(script).expect_err("duplicate tool");
        assert!(fault.message.contains("more than one MCP call started"));
    }

    #[test]
    fn strict_session_rejects_unknown_candidate_claim() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        let payload = LiveCandidatePayload {
            summary: "invalid claim".to_owned(),
            satisfied_criterion_ids: [id("criterion:unknown")].into_iter().collect(),
            proof_refs: BTreeSet::new(),
            requested_effects: BTreeSet::new(),
        };
        script[5]["params"]["item"]["text"] =
            json!(serde_json::to_string(&payload).expect("payload"));
        let fault = run_script(script).expect_err("unknown claim");
        assert!(fault.message.contains("unknown criterion"));
    }

    #[test]
    fn candidate_parser_rejects_duplicate_set_members_without_schema_support() {
        let (request, _) = protocol_exchange();
        let text = r#"{
            "summary":"duplicate claim",
            "satisfied_criterion_ids":["criterion:live_parser","criterion:live_parser"],
            "proof_refs":[],
            "requested_effects":[]
        }"#;
        let fault = parse_candidate_json(text, &request).expect_err("duplicate set member");
        assert!(fault.message.contains("duplicate"));
    }

    #[test]
    fn strict_session_rejects_terminal_correlation_mismatch() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[6]["params"]["turn"]["id"] = json!("turn-other");
        let fault = run_script(script).expect_err("terminal correlation");
        assert!(fault.message.contains("terminal notification correlation"));
    }

    #[test]
    fn strict_session_requires_returned_thread_authority_to_match_request() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[1]["result"]["sandbox"] = json!({"type":"workspaceWrite","networkAccess":false});
        let fault = run_script(script).expect_err("expanded returned sandbox");
        assert!(fault.message.contains("read-only no-network"));
    }

    #[test]
    fn strict_session_rejects_tampered_structured_response() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[4]["params"]["item"]["result"]["structuredContent"]["request_id"] =
            json!("request:tampered");
        let fault = run_script(script).expect_err("tampered response");
        assert!(
            fault.message.contains("request") || fault.message.contains("verification"),
            "{}",
            fault.message
        );
    }

    #[test]
    fn strict_session_rejects_completed_call_identity_substitution() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script[4]["params"]["item"]["id"] = json!("call-other");
        let fault = run_script(script).expect_err("substituted call id");
        assert!(
            fault
                .message
                .contains("differs from the single started call")
        );
    }

    #[test]
    fn strict_session_rejects_duplicate_final_candidate() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script.insert(6, script[5].clone());
        let fault = run_script(script).expect_err("duplicate final");
        assert!(fault.message.contains("more than one final"));
    }

    #[test]
    fn config_digest_text_requires_canonical_lowercase_sha256() {
        assert!(validate_sha256_text(&"ab".repeat(32), "fixture").is_ok());
        let uppercase = "AB".repeat(32);
        let fault = validate_sha256_text(&uppercase, "fixture").expect_err("uppercase digest");
        assert!(fault.message.contains("malformed"));
        assert!(validate_sha256_text("abc", "fixture").is_err());
    }

    #[test]
    fn streaming_file_hash_and_regular_file_pin_are_exact() {
        let directory =
            std::env::temp_dir().join(format!("cantor-live-hash-test-{}", std::process::id()));
        fs::create_dir_all(&directory).expect("temporary directory");
        let path = directory.join("artifact.bin");
        fs::write(&path, b"cantor-live-hash-fixture").expect("temporary fixture");
        let digest = sha256_file(&path).expect("file digest");
        assert_eq!(
            digest,
            "a263f9b8dbba6c17456ace6548f2435db44b2c3fe56d7949d53cf5497cc76062"
        );
        let canonical = validate_regular_file(&path, &digest, "fixture").expect("exact file pin");
        assert!(canonical.is_absolute());
        let fault =
            validate_regular_file(&path, &"00".repeat(32), "fixture").expect_err("wrong file pin");
        assert!(fault.message.contains("differs"));
        fs::remove_file(&path).expect("remove temporary fixture");
        fs::remove_dir(&directory).expect("remove temporary directory");
    }

    #[test]
    fn commentary_agent_message_does_not_substitute_for_final_candidate() {
        let (request, response) = protocol_exchange();
        let mut script = successful_script(&request, &response);
        script.insert(
            3,
            json!({"jsonrpc":"2.0","method":"item/completed","params":{
                "threadId":"thread-live","turnId":"turn-live","completedAtMs":0,
                "item":{"type":"agentMessage","id":"commentary","phase":"commentary",
                        "text":"I will use the exact read-only Cantor route."}
            }}),
        );
        let result = run_script(script).expect("commentary is passive");
        assert_eq!(result.evidence.mcp_call_id, "call-live");
    }
}
