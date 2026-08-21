//! Bounded experiment bridge from model-facing lifecycle commands to the
//! closed Slice 8 and Slice 10 MCP subprocesses.
//!
//! The host owns governed request injection. Models never author request
//! bodies, signatures, trust records, observations, receipts, or handles.

use std::{collections::BTreeMap, error::Error, fmt, path::Path, time::Duration};

use cantor_core::{
    ContentDigest, NativeLifecycleCustodyHandle, NativeLifecycleValidationOutcome,
    NativeLifecycleValidationRequest, NativeLifecycleValidationResponse,
    validate_native_lifecycle_request,
};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::{RoleClient, RunningService},
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::{process::Command, time::timeout};

mod evidence;

pub use evidence::{
    EvidenceVerificationFault, PROVIDER_INDEPENDENT_CONTRACT,
    PROVIDER_INDEPENDENT_EVIDENCE_MAX_BYTES, PROVIDER_INDEPENDENT_PROBE_NAME, ProbeComparison,
    ProbePhase, ProbeRestartTrial, ProviderIndependentProbeReport, ProviderIndependentProbeTrial,
    VerifiedProbeEvidence, verify_provider_independent_probe,
};

pub const STATELESS_TOOL_NAME: &str = "validate_native_lifecycle";
pub const CUSTODY_TOOL_NAME: &str = "manage_native_lifecycle_custody";
pub const MAX_STRUCTURED_RESPONSE_BYTES: usize = 131_072;
pub const MAX_FAULT_CHARACTERS: usize = 1_000;

const VALID_FIXTURE_BYTES: &[u8] =
    include_bytes!("../../../fixtures/semantic_compiler/native_lifecycle_valid_request.json");
const REFUSED_FIXTURE_BYTES: &[u8] =
    include_bytes!("../../../fixtures/semantic_compiler/native_lifecycle_refused_request.json");

type McpClient = RunningService<RoleClient, ()>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleFixtureCase {
    Valid,
    LifecycleRefused,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedLifecycleFixture {
    pub case: LifecycleFixtureCase,
    pub fixture_id: &'static str,
    pub request_bytes: &'static [u8],
    pub request: NativeLifecycleValidationRequest,
    pub direct_response: NativeLifecycleValidationResponse,
    pub direct_response_bytes: Vec<u8>,
}

impl GovernedLifecycleFixture {
    pub fn load(case: LifecycleFixtureCase) -> Result<Self, BridgeFault> {
        let (
            fixture_id,
            request_bytes,
            expected_request_bytes,
            expected_request_sha256,
            expected_response_bytes,
            expected_response_sha256,
            expected_outcome,
        ) = match case {
            LifecycleFixtureCase::Valid => (
                "native-lifecycle-valid-r1",
                VALID_FIXTURE_BYTES,
                31_018,
                "6C9B3BDC5B6CF1DC3355B6FADBB7FF7C4E8245B15A723C4DC9C4FEB7C3105E47",
                1_038,
                "ACD7248EDAB82C1947930D5E1FA792428DB2B8B743D6825D7AA903494A29AA14",
                NativeLifecycleValidationOutcome::ArtifactValid,
            ),
            LifecycleFixtureCase::LifecycleRefused => (
                "native-lifecycle-refused-unsupported-protocol-r1",
                REFUSED_FIXTURE_BYTES,
                31_030,
                "8B5073B182FC356A75C2EC76CA622D68B3C8A231AC0582FA0B6F8DB918644107",
                801,
                "32AD9119B2C31BDE54F04088E84BCDF6A4F3986917925289FCE269E68185D4B3",
                NativeLifecycleValidationOutcome::LifecycleRefused,
            ),
        };

        ensure_equal(
            "fixture_request_bytes",
            request_bytes.len(),
            expected_request_bytes,
        )?;
        ensure_equal(
            "fixture_request_sha256",
            sha256_hex(request_bytes),
            expected_request_sha256.to_owned(),
        )?;
        let request: NativeLifecycleValidationRequest = serde_json::from_slice(request_bytes)
            .map_err(|error| BridgeFault::fixture("fixture_decode", error))?;
        ensure_equal(
            "fixture_canonical_bytes",
            serde_json::to_vec(&request)
                .map_err(|error| BridgeFault::fixture("fixture_encode", error))?,
            request_bytes.to_vec(),
        )?;

        let direct_response = validate_native_lifecycle_request(&request);
        let direct_response_bytes = serde_json::to_vec(&direct_response)
            .map_err(|error| BridgeFault::fixture("direct_response_encode", error))?;
        ensure_equal(
            "direct_response_outcome",
            direct_response.outcome.clone(),
            expected_outcome,
        )?;
        ensure_equal(
            "direct_response_bytes",
            direct_response_bytes.len(),
            expected_response_bytes,
        )?;
        ensure_equal(
            "direct_response_sha256",
            sha256_hex(&direct_response_bytes),
            expected_response_sha256.to_owned(),
        )?;

        Ok(Self {
            case,
            fixture_id,
            request_bytes,
            request,
            direct_response,
            direct_response_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpArm {
    Stateless,
    VolatileCustody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeFaultKind {
    Fixture,
    ProcessStart,
    InitializationTimeout,
    Initialization,
    ToolMetadata,
    CallTimeout,
    Protocol,
    ResponseBound,
    ResponseDecode,
    SemanticMismatch,
    Custody,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeFault {
    pub kind: BridgeFaultKind,
    pub field: String,
    pub detail: String,
}

impl BridgeFault {
    fn new(kind: BridgeFaultKind, field: impl Into<String>, detail: impl fmt::Display) -> Self {
        Self {
            kind,
            field: bounded(field.into()),
            detail: bounded(detail.to_string()),
        }
    }

    fn fixture(field: impl Into<String>, detail: impl fmt::Display) -> Self {
        Self::new(BridgeFaultKind::Fixture, field, detail)
    }
}

impl fmt::Display for BridgeFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?}: {}: {}",
            self.kind, self.field, self.detail
        )
    }
}

impl Error for BridgeFault {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeObservation {
    pub arm: McpArm,
    pub fixture_id: String,
    pub argument_bytes: usize,
    pub structured_response_bytes: usize,
    pub mcp_is_error: bool,
    pub elapsed_microseconds: u64,
    pub exact_direct_response: bool,
    pub lifecycle_response: NativeLifecycleValidationResponse,
}

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
pub struct CustodyWireResponse {
    pub profile: String,
    pub operation: CustodyOperation,
    pub status: CustodyStatus,
    pub registry: Option<CustodyRegistrySummary>,
    pub handle: Option<NativeLifecycleCustodyHandle>,
    pub lifecycle_response: Option<NativeLifecycleValidationResponse>,
    pub fault: Option<CustodyFault>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationObservation {
    pub fixture_id: String,
    pub argument_bytes: usize,
    pub structured_response_bytes: usize,
    pub elapsed_microseconds: u64,
    pub handle: NativeLifecycleCustodyHandle,
}

pub struct StatelessSession {
    client: McpClient,
    operation_timeout: Duration,
}

impl StatelessSession {
    pub async fn open(binary: &Path, operation_timeout: Duration) -> Result<Self, BridgeFault> {
        let client = open_client(binary, STATELESS_TOOL_NAME, operation_timeout).await?;
        Ok(Self {
            client,
            operation_timeout,
        })
    }

    pub async fn validate(
        &self,
        fixture: &GovernedLifecycleFixture,
    ) -> Result<BridgeObservation, BridgeFault> {
        let arguments = object(json!({ "request": fixture.request.clone() }))?;
        let argument_bytes = encoded_len(&Value::Object(arguments.clone()), "stateless_arguments")?;
        let started = std::time::Instant::now();
        let result = call_tool(
            &self.client,
            STATELESS_TOOL_NAME,
            arguments,
            self.operation_timeout,
        )
        .await?;
        let elapsed_microseconds = elapsed_microseconds(started);
        decode_lifecycle_observation(
            McpArm::Stateless,
            fixture,
            argument_bytes,
            elapsed_microseconds,
            result,
        )
    }

    pub async fn close(mut self) -> Result<(), BridgeFault> {
        close_client(&mut self.client, self.operation_timeout).await
    }
}

pub struct CustodySession {
    client: McpClient,
    operation_timeout: Duration,
    handles: BTreeMap<LifecycleFixtureCase, NativeLifecycleCustodyHandle>,
}

impl CustodySession {
    pub async fn open(binary: &Path, operation_timeout: Duration) -> Result<Self, BridgeFault> {
        let client = open_client(binary, CUSTODY_TOOL_NAME, operation_timeout).await?;
        Ok(Self {
            client,
            operation_timeout,
            handles: BTreeMap::new(),
        })
    }

    pub async fn register(
        &mut self,
        fixture: &GovernedLifecycleFixture,
    ) -> Result<RegistrationObservation, BridgeFault> {
        if self.handles.contains_key(&fixture.case) {
            return Err(BridgeFault::new(
                BridgeFaultKind::Custody,
                "duplicate_registration",
                fixture.fixture_id,
            ));
        }
        let arguments = object(json!({
            "command": {"operation": "register", "request": fixture.request.clone()}
        }))?;
        let argument_bytes = encoded_len(&Value::Object(arguments.clone()), "register_arguments")?;
        let started = std::time::Instant::now();
        let result = call_tool(
            &self.client,
            CUSTODY_TOOL_NAME,
            arguments,
            self.operation_timeout,
        )
        .await?;
        let elapsed_microseconds = elapsed_microseconds(started);
        let (wire, structured_response_bytes, mcp_is_error) = decode_custody_result(result)?;
        ensure_equal("register_mcp_is_error", mcp_is_error, false)?;
        ensure_equal(
            "register_operation",
            wire.operation,
            CustodyOperation::Register,
        )?;
        ensure_equal("register_status", wire.status, CustodyStatus::Registered)?;
        ensure_equal("register_lifecycle_response", wire.lifecycle_response, None)?;
        let handle = wire.handle.ok_or_else(|| {
            BridgeFault::new(BridgeFaultKind::Custody, "register_handle", "missing")
        })?;
        self.handles.insert(fixture.case, handle.clone());
        Ok(RegistrationObservation {
            fixture_id: fixture.fixture_id.to_owned(),
            argument_bytes,
            structured_response_bytes,
            elapsed_microseconds,
            handle,
        })
    }

    pub fn handle(&self, case: LifecycleFixtureCase) -> Option<&NativeLifecycleCustodyHandle> {
        self.handles.get(&case)
    }

    pub async fn validate(
        &self,
        fixture: &GovernedLifecycleFixture,
    ) -> Result<BridgeObservation, BridgeFault> {
        let handle = self.handles.get(&fixture.case).ok_or_else(|| {
            BridgeFault::new(
                BridgeFaultKind::Custody,
                "unregistered_fixture",
                fixture.fixture_id,
            )
        })?;
        let (wire, argument_bytes, structured_response_bytes, mcp_is_error, elapsed_microseconds) =
            self.call_validate(handle).await?;
        ensure_equal(
            "validate_operation",
            wire.operation,
            CustodyOperation::Validate,
        )?;
        ensure_equal("validate_status", wire.status, CustodyStatus::Validated)?;
        let lifecycle_response = wire.lifecycle_response.ok_or_else(|| {
            BridgeFault::new(
                BridgeFaultKind::Custody,
                "validate_lifecycle_response",
                "missing",
            )
        })?;
        ensure_response_matches(fixture, &lifecycle_response, mcp_is_error)?;
        Ok(BridgeObservation {
            arm: McpArm::VolatileCustody,
            fixture_id: fixture.fixture_id.to_owned(),
            argument_bytes,
            structured_response_bytes,
            mcp_is_error,
            elapsed_microseconds,
            exact_direct_response: true,
            lifecycle_response,
        })
    }

    pub async fn validate_raw_handle(
        &self,
        handle: &NativeLifecycleCustodyHandle,
    ) -> Result<CustodyWireResponse, BridgeFault> {
        let (wire, _, _, _, _) = self.call_validate(handle).await?;
        Ok(wire)
    }

    async fn call_validate(
        &self,
        handle: &NativeLifecycleCustodyHandle,
    ) -> Result<(CustodyWireResponse, usize, usize, bool, u64), BridgeFault> {
        let arguments = object(json!({
            "command": {"operation": "validate", "handle": handle}
        }))?;
        let argument_bytes = encoded_len(&Value::Object(arguments.clone()), "validate_arguments")?;
        let started = std::time::Instant::now();
        let result = call_tool(
            &self.client,
            CUSTODY_TOOL_NAME,
            arguments,
            self.operation_timeout,
        )
        .await?;
        let elapsed_microseconds = elapsed_microseconds(started);
        let (wire, structured_response_bytes, mcp_is_error) = decode_custody_result(result)?;
        Ok((
            wire,
            argument_bytes,
            structured_response_bytes,
            mcp_is_error,
            elapsed_microseconds,
        ))
    }

    pub async fn close(mut self) -> Result<(), BridgeFault> {
        close_client(&mut self.client, self.operation_timeout).await
    }
}

async fn open_client(
    binary: &Path,
    expected_tool: &str,
    operation_timeout: Duration,
) -> Result<McpClient, BridgeFault> {
    if !binary.is_file() {
        return Err(BridgeFault::new(
            BridgeFaultKind::ProcessStart,
            "binary",
            format!("not a file: {}", binary.display()),
        ));
    }
    let transport = TokioChildProcess::new(Command::new(binary).configure(|_| {}))
        .map_err(|error| BridgeFault::new(BridgeFaultKind::ProcessStart, "subprocess", error))?;
    let client = timeout(operation_timeout, ().serve(transport))
        .await
        .map_err(|_| {
            BridgeFault::new(
                BridgeFaultKind::InitializationTimeout,
                "initialize",
                format!("exceeded {} ms", operation_timeout.as_millis()),
            )
        })?
        .map_err(|error| BridgeFault::new(BridgeFaultKind::Initialization, "initialize", error))?;
    let tools = timeout(operation_timeout, client.list_all_tools())
        .await
        .map_err(|_| {
            BridgeFault::new(
                BridgeFaultKind::InitializationTimeout,
                "tools_list",
                format!("exceeded {} ms", operation_timeout.as_millis()),
            )
        })?
        .map_err(|error| BridgeFault::new(BridgeFaultKind::Protocol, "tools_list", error))?;
    if tools.len() != 1 || tools[0].name.as_ref() != expected_tool {
        return Err(BridgeFault::new(
            BridgeFaultKind::ToolMetadata,
            "tool_set",
            format!(
                "expected [{expected_tool}], received {:?}",
                tools
                    .iter()
                    .map(|tool| tool.name.as_ref())
                    .collect::<Vec<_>>()
            ),
        ));
    }
    Ok(client)
}

async fn call_tool(
    client: &McpClient,
    tool_name: &str,
    arguments: Map<String, Value>,
    operation_timeout: Duration,
) -> Result<CallToolResult, BridgeFault> {
    timeout(
        operation_timeout,
        client
            .call_tool(CallToolRequestParams::new(tool_name.to_owned()).with_arguments(arguments)),
    )
    .await
    .map_err(|_| {
        BridgeFault::new(
            BridgeFaultKind::CallTimeout,
            "tools_call",
            format!("exceeded {} ms", operation_timeout.as_millis()),
        )
    })?
    .map_err(|error| BridgeFault::new(BridgeFaultKind::Protocol, "tools_call", error))
}

fn decode_lifecycle_observation(
    arm: McpArm,
    fixture: &GovernedLifecycleFixture,
    argument_bytes: usize,
    elapsed_microseconds: u64,
    result: CallToolResult,
) -> Result<BridgeObservation, BridgeFault> {
    let mcp_is_error = result.is_error.ok_or_else(|| {
        BridgeFault::new(
            BridgeFaultKind::Protocol,
            "mcp_is_error",
            "missing explicit value",
        )
    })?;
    let structured = result.structured_content.ok_or_else(|| {
        BridgeFault::new(BridgeFaultKind::Protocol, "structured_content", "missing")
    })?;
    let structured_response_bytes = encoded_len(&structured, "structured_content")?;
    let lifecycle_response: NativeLifecycleValidationResponse = serde_json::from_value(structured)
        .map_err(|error| {
            BridgeFault::new(BridgeFaultKind::ResponseDecode, "lifecycle_response", error)
        })?;
    ensure_response_matches(fixture, &lifecycle_response, mcp_is_error)?;
    Ok(BridgeObservation {
        arm,
        fixture_id: fixture.fixture_id.to_owned(),
        argument_bytes,
        structured_response_bytes,
        mcp_is_error,
        elapsed_microseconds,
        exact_direct_response: true,
        lifecycle_response,
    })
}

fn decode_custody_result(
    result: CallToolResult,
) -> Result<(CustodyWireResponse, usize, bool), BridgeFault> {
    let mcp_is_error = result.is_error.ok_or_else(|| {
        BridgeFault::new(
            BridgeFaultKind::Protocol,
            "mcp_is_error",
            "missing explicit value",
        )
    })?;
    let structured = result.structured_content.ok_or_else(|| {
        BridgeFault::new(BridgeFaultKind::Protocol, "structured_content", "missing")
    })?;
    let structured_response_bytes = encoded_len(&structured, "structured_content")?;
    let wire: CustodyWireResponse = serde_json::from_value(structured).map_err(|error| {
        BridgeFault::new(BridgeFaultKind::ResponseDecode, "custody_response", error)
    })?;
    Ok((wire, structured_response_bytes, mcp_is_error))
}

fn ensure_response_matches(
    fixture: &GovernedLifecycleFixture,
    response: &NativeLifecycleValidationResponse,
    mcp_is_error: bool,
) -> Result<(), BridgeFault> {
    ensure_equal("lifecycle_response", response, &fixture.direct_response)?;
    let expected_is_error = matches!(
        fixture.direct_response.outcome,
        NativeLifecycleValidationOutcome::LifecycleRefused
            | NativeLifecycleValidationOutcome::InputRefused
    );
    ensure_equal("mcp_is_error", mcp_is_error, expected_is_error)
}

fn object(value: Value) -> Result<Map<String, Value>, BridgeFault> {
    value.as_object().cloned().ok_or_else(|| {
        BridgeFault::new(BridgeFaultKind::Fixture, "tool_arguments", "not an object")
    })
}

fn encoded_len(value: &Value, field: &str) -> Result<usize, BridgeFault> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| BridgeFault::new(BridgeFaultKind::ResponseDecode, field, error))?
        .len();
    if bytes > MAX_STRUCTURED_RESPONSE_BYTES {
        return Err(BridgeFault::new(
            BridgeFaultKind::ResponseBound,
            field,
            format!("{bytes} exceeds {MAX_STRUCTURED_RESPONSE_BYTES}"),
        ));
    }
    Ok(bytes)
}

fn ensure_equal<T>(field: &str, actual: T, expected: T) -> Result<(), BridgeFault>
where
    T: PartialEq + fmt::Debug,
{
    if actual == expected {
        Ok(())
    } else {
        Err(BridgeFault::new(
            BridgeFaultKind::SemanticMismatch,
            field,
            format!("expected {expected:?}, received {actual:?}"),
        ))
    }
}

async fn close_client(
    client: &mut McpClient,
    operation_timeout: Duration,
) -> Result<(), BridgeFault> {
    match client
        .close_with_timeout(operation_timeout.min(Duration::from_secs(5)))
        .await
    {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(BridgeFault::new(
            BridgeFaultKind::Shutdown,
            "subprocess",
            "shutdown timed out",
        )),
        Err(error) => Err(BridgeFault::new(
            BridgeFaultKind::Shutdown,
            "subprocess",
            error,
        )),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn elapsed_microseconds(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn bounded(value: String) -> String {
    value.chars().take(MAX_FAULT_CHARACTERS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governed_fixtures_match_exact_direct_oracles() {
        for case in [
            LifecycleFixtureCase::Valid,
            LifecycleFixtureCase::LifecycleRefused,
        ] {
            let fixture = GovernedLifecycleFixture::load(case).expect("governed fixture");
            assert_eq!(fixture.request_bytes.last(), Some(&b'}'));
            assert_eq!(
                fixture.direct_response_bytes.len(),
                if case == LifecycleFixtureCase::Valid {
                    1_038
                } else {
                    801
                }
            );
        }
    }

    #[test]
    fn bridge_fault_text_is_bounded() {
        let fault = BridgeFault::new(
            BridgeFaultKind::Protocol,
            "x".repeat(2_000),
            "y".repeat(2_000),
        );
        assert_eq!(fault.field.chars().count(), MAX_FAULT_CHARACTERS);
        assert_eq!(fault.detail.chars().count(), MAX_FAULT_CHARACTERS);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn absent_subprocess_refuses_before_transport_initialization() {
        let fault = match StatelessSession::open(
            Path::new("definitely-absent-cantor-compiler-mcp"),
            Duration::from_millis(10),
        )
        .await
        {
            Ok(_) => panic!("absent subprocess must refuse"),
            Err(fault) => fault,
        };
        assert_eq!(fault.kind, BridgeFaultKind::ProcessStart);
        assert_eq!(fault.field, "binary");
    }
}
