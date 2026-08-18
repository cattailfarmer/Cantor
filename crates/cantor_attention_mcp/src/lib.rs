//! Experimental, read-only MCP projection of the verified Needle route-only runtime.
//!
//! This adapter is deliberately separate from `cantor_mcp`: it returns learned
//! routing proposals backed by verified evidence, never signed SOP authority.

#![recursion_limit = "512"]

use std::{
    fmt, fs,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
use sha2::{Digest as _, Sha256};
use tokio::{process::Command, time::sleep};

pub const TOOL_NAME: &str = "route_attention";
pub const ADAPTER_PROFILE: &str = "cantor-route-attention-mcp-result/0.1";
pub const CONFIG_PROFILE: &str = "cantor-route-attention-mcp-config/0.1";
pub const RUNTIME_PROFILE: &str = "cantor-needle-runtime-result/0.2";
const MAX_CONFIG_BYTES: usize = 65_536;
const HARD_MAX_INPUT_BYTES: usize = 65_536;
const HARD_MAX_OUTPUT_BYTES: usize = 1_048_576;
const HARD_MAX_TIMEOUT_MILLISECONDS: u64 = 120_000;
static NEXT_CAPTURE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionMcpConfig {
    pub profile: String,
    pub python: PathBuf,
    pub controller: PathBuf,
    pub runtime_config: PathBuf,
    pub expected_controller_sha256: String,
    pub expected_runtime_config_sha256: String,
    pub expected_deployment_manifest_sha256: String,
    pub expected_catalogue_digest: String,
    pub timeout_milliseconds: u64,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct AttentionMcpServer {
    runtime: Arc<PinnedRuntime>,
}

#[derive(Clone, Debug)]
struct PinnedRuntime {
    python: PathBuf,
    controller: PathBuf,
    runtime_config: PathBuf,
    expected_controller_sha256: String,
    expected_runtime_config_sha256: String,
    expected_deployment_manifest_sha256: String,
    expected_catalogue_digest: String,
    timeout: Duration,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterFault {
    pub code: &'static str,
    pub message: String,
}

impl fmt::Display for AdapterFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AdapterFault {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteArguments {
    stimulus: String,
}

struct ProcessResult {
    status: ExitStatus,
    value: Value,
}

struct TempCapture {
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl AttentionMcpServer {
    pub async fn new(config: AttentionMcpConfig) -> Result<Self, AdapterFault> {
        let runtime = PinnedRuntime::from_config(config)?;
        runtime.preflight().await?;
        Ok(Self {
            runtime: Arc::new(runtime),
        })
    }

    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Propose one hardened attention procedure for caller stimulus through the pinned Needle route-only runtime. A successful proposal is independently evidence-verified, but is not signed SOP authority and does not authorize query_sop or any effect.",
            input_schema(),
        )
        .with_title("Route attention")
        .with_raw_output_schema(Arc::new(output_schema()))
        .with_annotations(
            ToolAnnotations::with_title("Route attention")
                .read_only(true)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        )
    }

    pub async fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let value = Value::Object(arguments.unwrap_or_default());
        let parsed: RouteArguments = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => return tool_fault("invalid_arguments", bounded(&error.to_string())),
        };
        let stimulus_bytes = parsed.stimulus.len();
        if stimulus_bytes == 0 || stimulus_bytes > self.runtime.max_input_bytes {
            return tool_fault(
                "stimulus_limit_violation",
                format!(
                    "stimulus contains {stimulus_bytes} UTF-8 bytes; allowed range is 1..={}",
                    self.runtime.max_input_bytes
                ),
            );
        }
        match self.runtime.route(&parsed.stimulus).await {
            Ok((runtime, verification)) => structured_result(
                json!({
                    "profile": ADAPTER_PROFILE,
                    "status": "route_selected",
                    "runtime": runtime,
                    "verification": verification,
                    "authority": "learned_evidence_backed_proposal"
                }),
                false,
                "Cantor attention route selected and evidence-verified; treat it as a learned proposal, not signed SOP authority.".to_owned(),
            ),
            Err(fault) => tool_fault(fault.code, fault.message),
        }
    }
}

impl ServerHandler for AttentionMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-attention", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor learned attention router")
                    .with_description("Evidence-verified route-only attention proposals through one read-only tool."),
            )
            .with_instructions(
                "Use route_attention only to propose which hardened attention procedure may apply. Treat structuredContent as evidence-backed learned routing, not signed meaning, truth, authorization, or permission to invoke query_sop. Preserve all faults and do not invent a route when the tool refuses.",
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
        Ok(self.execute_tool_arguments(request.arguments).await.into())
    }
}

impl PinnedRuntime {
    fn from_config(config: AttentionMcpConfig) -> Result<Self, AdapterFault> {
        if config.profile != CONFIG_PROFILE {
            return Err(fault("invalid_config", "unknown configuration profile"));
        }
        if config.timeout_milliseconds == 0
            || config.timeout_milliseconds > HARD_MAX_TIMEOUT_MILLISECONDS
        {
            return Err(fault(
                "invalid_config",
                "timeout is outside the closed bound",
            ));
        }
        if config.max_input_bytes == 0 || config.max_input_bytes > HARD_MAX_INPUT_BYTES {
            return Err(fault(
                "invalid_config",
                "input limit is outside the closed bound",
            ));
        }
        if config.max_output_bytes == 0 || config.max_output_bytes > HARD_MAX_OUTPUT_BYTES {
            return Err(fault(
                "invalid_config",
                "output limit is outside the closed bound",
            ));
        }
        for digest in [
            &config.expected_controller_sha256,
            &config.expected_runtime_config_sha256,
            &config.expected_deployment_manifest_sha256,
            &config.expected_catalogue_digest,
        ] {
            if !is_digest(digest) {
                return Err(fault(
                    "invalid_config",
                    "expected digest is not lowercase SHA-256",
                ));
            }
        }
        let python = canonical_file(&config.python, "python")?;
        let controller = canonical_file(&config.controller, "controller")?;
        let runtime_config = canonical_file(&config.runtime_config, "runtime_config")?;
        require_digest(
            &controller,
            &config.expected_controller_sha256,
            "controller",
        )?;
        require_digest(
            &runtime_config,
            &config.expected_runtime_config_sha256,
            "runtime_config",
        )?;
        let runtime_config_value: Value =
            serde_json::from_slice(&read_bounded(&runtime_config, MAX_CONFIG_BYTES)?)
                .map_err(|_| fault("invalid_runtime_config", "runtime config is not valid JSON"))?;
        let recorded_deployment = runtime_config_value
            .get("deployment_manifest_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                fault(
                    "invalid_runtime_config",
                    "runtime config omits deployment identity",
                )
            })?;
        if recorded_deployment != config.expected_deployment_manifest_sha256 {
            return Err(fault(
                "runtime_identity_mismatch",
                "runtime config deployment identity differs from adapter pin",
            ));
        }
        Ok(Self {
            python,
            controller,
            runtime_config,
            expected_controller_sha256: config.expected_controller_sha256,
            expected_runtime_config_sha256: config.expected_runtime_config_sha256,
            expected_deployment_manifest_sha256: config.expected_deployment_manifest_sha256,
            expected_catalogue_digest: config.expected_catalogue_digest,
            timeout: Duration::from_millis(config.timeout_milliseconds),
            max_input_bytes: config.max_input_bytes,
            max_output_bytes: config.max_output_bytes,
        })
    }

    async fn preflight(&self) -> Result<(), AdapterFault> {
        let health = self.invoke(["health"]).await?;
        if !health.status.success() {
            return Err(fault(
                "runtime_health_failed",
                "runtime health command failed",
            ));
        }
        require_string(
            &health.value,
            "profile",
            RUNTIME_PROFILE,
            "runtime_health_invalid",
        )?;
        require_string(&health.value, "status", "healthy", "runtime_health_invalid")?;
        require_string(
            &health.value,
            "catalogue_digest",
            &self.expected_catalogue_digest,
            "runtime_health_invalid",
        )?;
        let deployment = health
            .value
            .get("deployment")
            .and_then(Value::as_object)
            .ok_or_else(|| fault("runtime_health_invalid", "health omits deployment object"))?;
        if deployment.get("manifest_sha256").and_then(Value::as_str)
            != Some(&self.expected_deployment_manifest_sha256)
        {
            return Err(fault(
                "runtime_health_invalid",
                "health deployment identity differs from adapter pin",
            ));
        }
        Ok(())
    }

    async fn route(&self, stimulus: &str) -> Result<(Value, Value), AdapterFault> {
        let run = self
            .invoke(["run", "--text", stimulus, "--route-only"])
            .await?;
        require_string(
            &run.value,
            "profile",
            RUNTIME_PROFILE,
            "runtime_result_invalid",
        )?;
        if !run.status.success()
            || run.value.get("status").and_then(Value::as_str) != Some("route_selected")
        {
            let code = run
                .value
                .pointer("/fault/code")
                .and_then(Value::as_str)
                .unwrap_or("runtime_refused");
            return Err(AdapterFault {
                code: "runtime_refused",
                message: bounded(code),
            });
        }
        let run_id = required_uuid(&run.value, "run_id")?;
        required_digest(&run.value, "catalogue_digest")?;
        required_digest(&run.value, "procedure_digest")?;
        required_digest(&run.value, "admission_account_digest")?;
        if !run.value.get("procedure_id").is_some_and(Value::is_string)
            || !run
                .value
                .get("admission_account")
                .is_some_and(Value::is_object)
        {
            return Err(fault(
                "runtime_result_invalid",
                "selected result omits proposal identity or account",
            ));
        }
        let verified = self.invoke(["verify", "--id", run_id]).await?;
        if !verified.status.success() {
            return Err(fault(
                "evidence_verification_failed",
                "runtime verifier command failed",
            ));
        }
        require_string(
            &verified.value,
            "profile",
            RUNTIME_PROFILE,
            "evidence_verification_failed",
        )?;
        require_string(
            &verified.value,
            "status",
            "verified",
            "evidence_verification_failed",
        )?;
        require_string(
            &verified.value,
            "evidence_kind",
            "run",
            "evidence_verification_failed",
        )?;
        require_string(
            &verified.value,
            "evidence_id",
            run_id,
            "evidence_verification_failed",
        )?;
        require_string(
            &verified.value,
            "recorded_status",
            "route_selected",
            "evidence_verification_failed",
        )?;
        require_string(
            &verified.value,
            "admission_account",
            "verified",
            "evidence_verification_failed",
        )?;
        required_digest(&verified.value, "manifest_sha256")?;
        Ok((run.value, verified.value))
    }

    async fn invoke<'a, I>(&self, arguments: I) -> Result<ProcessResult, AdapterFault>
    where
        I: IntoIterator<Item = &'a str>,
    {
        require_digest(
            &self.controller,
            &self.expected_controller_sha256,
            "controller",
        )?;
        require_digest(
            &self.runtime_config,
            &self.expected_runtime_config_sha256,
            "runtime_config",
        )?;
        let mut command = Command::new(&self.python);
        let (capture, stdout, stderr) = TempCapture::new()?;
        command
            .arg(&self.controller)
            .arg("--config")
            .arg(&self.runtime_config)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| {
            fault(
                "runtime_transport_failed",
                "runtime process could not execute",
            )
        })?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| {
                fault(
                    "runtime_transport_failed",
                    "runtime process status could not be observed",
                )
            })? {
                break status;
            }
            if capture.exceeds(self.max_output_bytes)? {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(fault(
                    "runtime_output_limit_exceeded",
                    "runtime output exceeded the pinned byte limit",
                ));
            }
            if started.elapsed() >= self.timeout {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(fault(
                    "runtime_timeout",
                    "runtime command exceeded the pinned timeout",
                ));
            }
            sleep(Duration::from_millis(10)).await;
        };
        let (stdout_bytes, stderr_bytes) = capture.read()?;
        if stdout_bytes.len() > self.max_output_bytes || stderr_bytes.len() > self.max_output_bytes
        {
            return Err(fault(
                "runtime_output_limit_exceeded",
                "runtime output exceeded the pinned byte limit",
            ));
        }
        let stdout = std::str::from_utf8(&stdout_bytes)
            .map_err(|_| fault("runtime_output_invalid", "runtime stdout is not UTF-8"))?;
        let trimmed = stdout.trim();
        if trimmed.is_empty() || trimmed.lines().count() != 1 {
            return Err(fault(
                "runtime_output_invalid",
                "runtime stdout must contain exactly one JSON line",
            ));
        }
        let value = serde_json::from_str(trimmed)
            .map_err(|_| fault("runtime_output_invalid", "runtime stdout is not valid JSON"))?;
        Ok(ProcessResult { status, value })
    }
}

impl TempCapture {
    fn new() -> Result<(Self, fs::File, fs::File), AdapterFault> {
        let sequence = NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed);
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| fault("runtime_capture_failed", "system clock precedes epoch"))?
            .as_nanos();
        let base = format!(
            "cantor-attention-mcp-{}-{sequence}-{epoch}",
            std::process::id()
        );
        let stdout_path = std::env::temp_dir().join(format!("{base}.stdout"));
        let stderr_path = std::env::temp_dir().join(format!("{base}.stderr"));
        let stdout = create_capture(&stdout_path)?;
        let stderr = match create_capture(&stderr_path) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_file(&stdout_path);
                return Err(error);
            }
        };
        Ok((
            Self {
                stdout_path,
                stderr_path,
            },
            stdout,
            stderr,
        ))
    }

    fn exceeds(&self, limit: usize) -> Result<bool, AdapterFault> {
        Ok(capture_length(&self.stdout_path)? > limit as u64
            || capture_length(&self.stderr_path)? > limit as u64)
    }

    fn read(&self) -> Result<(Vec<u8>, Vec<u8>), AdapterFault> {
        let stdout = fs::read(&self.stdout_path).map_err(|_| {
            fault(
                "runtime_capture_failed",
                "runtime stdout capture cannot be read",
            )
        })?;
        let stderr = fs::read(&self.stderr_path).map_err(|_| {
            fault(
                "runtime_capture_failed",
                "runtime stderr capture cannot be read",
            )
        })?;
        Ok((stdout, stderr))
    }
}

impl Drop for TempCapture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.stdout_path);
        let _ = fs::remove_file(&self.stderr_path);
    }
}

fn create_capture(path: &Path) -> Result<fs::File, AdapterFault> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            fault(
                "runtime_capture_failed",
                "exclusive runtime capture cannot be created",
            )
        })
}

fn capture_length(path: &Path) -> Result<u64, AdapterFault> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|_| {
            fault(
                "runtime_capture_failed",
                "runtime capture metadata cannot be read",
            )
        })
}

pub fn load_config_file(path: &Path) -> Result<AttentionMcpConfig, AdapterFault> {
    if !path.is_absolute() {
        return Err(fault(
            "invalid_config_path",
            "adapter config path must be absolute",
        ));
    }
    let bytes = read_bounded(path, MAX_CONFIG_BYTES)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| fault("invalid_config", "adapter config is invalid or not closed"))
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, AdapterFault> {
    if !path.is_absolute() {
        return Err(fault(
            "invalid_config_path",
            format!("{label} path must be absolute"),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|_| {
        fault(
            "config_file_missing",
            format!("{label} path cannot be resolved"),
        )
    })?;
    if !fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file()) {
        return Err(fault(
            "config_file_missing",
            format!("{label} path is not a regular file"),
        ));
    }
    Ok(canonical)
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, AdapterFault> {
    let bytes = fs::read(path)
        .map_err(|_| fault("config_read_failed", "configured file cannot be read"))?;
    if bytes.len() > limit {
        return Err(fault(
            "config_limit_exceeded",
            "configured file exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

fn require_digest(path: &Path, expected: &str, label: &str) -> Result<(), AdapterFault> {
    let actual = hex_digest(
        &fs::read(path)
            .map_err(|_| fault("config_read_failed", format!("{label} cannot be read")))?,
    );
    if actual != expected {
        return Err(fault(
            "artifact_identity_mismatch",
            format!("{label} digest differs from adapter pin"),
        ));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn required_digest(value: &Value, field: &str) -> Result<(), AdapterFault> {
    match value.get(field).and_then(Value::as_str) {
        Some(digest) if is_digest(digest) => Ok(()),
        _ => Err(fault(
            "runtime_result_invalid",
            format!("{field} is not a canonical digest"),
        )),
    }
}

fn required_uuid<'a>(value: &'a Value, field: &str) -> Result<&'a str, AdapterFault> {
    let candidate = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| fault("runtime_result_invalid", format!("{field} is missing")))?;
    let valid = candidate.len() == 36
        && candidate.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        });
    if valid {
        Ok(candidate)
    } else {
        Err(fault(
            "runtime_result_invalid",
            format!("{field} is not a canonical UUID"),
        ))
    }
}

fn require_string(
    value: &Value,
    field: &str,
    expected: &str,
    code: &'static str,
) -> Result<(), AdapterFault> {
    if value.get(field).and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(fault(
            code,
            format!("{field} differs from the required identity"),
        ))
    }
}

fn fault(code: &'static str, message: impl Into<String>) -> AdapterFault {
    AdapterFault {
        code,
        message: bounded(&message.into()),
    }
}

fn tool_fault(code: &str, message: String) -> CallToolResult {
    structured_result(
        json!({ "profile": ADAPTER_PROFILE, "status": "fault", "fault": { "code": code, "message": message } }),
        true,
        format!("Cantor attention router fault: {code}."),
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

fn bounded(message: &str) -> String {
    message.chars().take(512).collect()
}

fn object(value: Value) -> JsonObject {
    value
        .as_object()
        .expect("static schema must be an object")
        .clone()
}

fn input_schema() -> JsonObject {
    object(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["stimulus"],
        "properties": {
            "stimulus": { "type": "string", "minLength": 1, "maxLength": 65536 }
        }
    }))
}

fn output_schema() -> JsonObject {
    object(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["profile", "status"],
        "properties": {
            "profile": { "type": "string", "const": ADAPTER_PROFILE },
            "status": { "type": "string", "enum": ["route_selected", "fault"] },
            "runtime": { "type": "object" },
            "verification": { "type": "object" },
            "authority": { "type": "string", "const": "learned_evidence_backed_proposal" },
            "fault": { "type": "object" }
        }
    }))
}
