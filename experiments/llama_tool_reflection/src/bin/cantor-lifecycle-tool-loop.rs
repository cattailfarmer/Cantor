use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cantor_lifecycle_tool_loop::{
    BridgeObservation, CustodySession, CustodyStatus, GovernedLifecycleFixture,
    LifecycleFixtureCase, McpArm, RegistrationObservation, StatelessSession,
};
use cantor_llama_tool_reflection::lifecycle_tool_loop::{
    LifecycleProjection, TranscriptFault, extract_imported_projection, extract_tool_invocation,
    first_request, lifecycle_projection, sanitize_response, second_request,
};
use reqwest::{Client, Response, Url};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PINNED_MODEL: &str = "gpt-oss-20b";
const PINNED_MODEL_PATH: &str =
    r"C:\Users\enjer\.lmstudio\models\lmstudio-community\gpt-oss-20b-GGUF\gpt-oss-20b-MXFP4.gguf";
const PINNED_PROVIDER_RELEASE: &str = "b10181";
const PINNED_SYSTEM_FINGERPRINT: &str = "b10181-caa596ab3";
const RELEASE_CONTRACT_SHA256: &str =
    "3960F225A4CAC13DCA62D0670EDEB95D846B0E05A29E80B68FFC86ECD6218720";
const RELEASE_CONTRACT_BYTES: &[u8] = include_bytes!("../../llama_cpp_release.sop");
const MAX_HTTP_BODY_BYTES: usize = 2_097_152;
const MAX_REPORT_BYTES: usize = 16_777_216;
const MAX_TRIALS_PER_CASE: usize = 8;
const MAX_WARMUPS_PER_CASE: usize = 2;

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
struct Config {
    base_url: String,
    model: String,
    expected_model_path: String,
    stateless_mcp_bin: PathBuf,
    custody_mcp_bin: PathBuf,
    output: PathBuf,
    timeout: Duration,
    measured_trials: usize,
    warmups: usize,
}

impl Config {
    fn parse() -> Result<Self, AnyError> {
        let executable_suffix = if cfg!(windows) { ".exe" } else { "" };
        let mut config = Self {
            base_url: "http://127.0.0.1:8080/v1".to_owned(),
            model: PINNED_MODEL.to_owned(),
            expected_model_path: PINNED_MODEL_PATH.to_owned(),
            stateless_mcp_bin: PathBuf::from(format!(
                "target/debug/cantor-compiler-mcp{executable_suffix}"
            )),
            custody_mcp_bin: PathBuf::from(format!(
                "target/debug/cantor-compiler-custody-mcp{executable_suffix}"
            )),
            output: PathBuf::from(
                "experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/latest.json",
            ),
            timeout: Duration::from_secs(180),
            measured_trials: 2,
            warmups: 1,
        };
        let mut args = env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--base-url" => config.base_url = required_value(&mut args, &argument)?,
                "--model" => config.model = required_value(&mut args, &argument)?,
                "--expected-model-path" => {
                    config.expected_model_path = required_value(&mut args, &argument)?;
                }
                "--stateless-mcp-bin" => {
                    config.stateless_mcp_bin = PathBuf::from(required_value(&mut args, &argument)?);
                }
                "--custody-mcp-bin" => {
                    config.custody_mcp_bin = PathBuf::from(required_value(&mut args, &argument)?);
                }
                "--output" => {
                    config.output = PathBuf::from(required_value(&mut args, &argument)?);
                }
                "--timeout-seconds" => {
                    config.timeout =
                        Duration::from_secs(required_value(&mut args, &argument)?.parse::<u64>()?);
                }
                "--trials" => {
                    config.measured_trials = required_value(&mut args, &argument)?.parse()?;
                }
                "--warmups" => config.warmups = required_value(&mut args, &argument)?.parse()?,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }
        config.base_url = config.base_url.trim_end_matches('/').to_owned();
        validate_config(&config)?;
        Ok(config)
    }
}

fn required_value(
    args: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, AnyError> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value").into())
}

fn validate_config(config: &Config) -> Result<(), AnyError> {
    let url = Url::parse(&config.base_url)?;
    if url.scheme() != "http" || !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
    {
        return Err("base URL must be an HTTP loopback endpoint".into());
    }
    if config.model != PINNED_MODEL {
        return Err(
            format!("provider_mismatch: model must remain pinned to {PINNED_MODEL}").into(),
        );
    }
    if !(1..=MAX_TRIALS_PER_CASE).contains(&config.measured_trials) {
        return Err(format!("trials must be 1..={MAX_TRIALS_PER_CASE}").into());
    }
    if config.warmups > MAX_WARMUPS_PER_CASE {
        return Err(format!("warmups must be 0..={MAX_WARMUPS_PER_CASE}").into());
    }
    if config.timeout.is_zero() || config.timeout > Duration::from_secs(600) {
        return Err("timeout must be 1..=600 seconds".into());
    }
    if !config.stateless_mcp_bin.is_file() {
        return Err(format!(
            "stateless MCP binary is absent: {}",
            config.stateless_mcp_bin.display()
        )
        .into());
    }
    if !config.custody_mcp_bin.is_file() {
        return Err(format!(
            "custody MCP binary is absent: {}",
            config.custody_mcp_bin.display()
        )
        .into());
    }
    if sha256_hex(RELEASE_CONTRACT_BYTES) != RELEASE_CONTRACT_SHA256 {
        return Err("pinned provider release contract digest mismatch".into());
    }
    Ok(())
}

fn print_help() {
    println!(
        "cantor-lifecycle-tool-loop\n\
         \n\
         Runs balanced governed lifecycle A/B trials through unmodified llama.cpp.\n\
         \n\
         Options:\n\
           --base-url URL             loopback OpenAI-compatible API root\n\
           --model NAME               pinned alias (must be gpt-oss-20b)\n\
           --expected-model-path PATH observed model path required in /props\n\
           --stateless-mcp-bin PATH   Slice8 stdio binary\n\
           --custody-mcp-bin PATH     Slice10 stdio binary\n\
           --output PATH              bounded sanitized JSON evidence\n\
           --timeout-seconds N        1..=600 per operation (default 180)\n\
           --trials N                 1..=8 measured trials per arm/case\n\
           --warmups N                0..=2 warmups per arm/case"
    );
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceFault {
    kind: String,
    detail: String,
}

impl EvidenceFault {
    fn new(kind: impl Into<String>, detail: impl ToString) -> Self {
        Self {
            kind: kind.into(),
            detail: detail.to_string().chars().take(2_000).collect(),
        }
    }
}

impl From<TranscriptFault> for EvidenceFault {
    fn from(value: TranscriptFault) -> Self {
        Self::new(value.kind, value.detail)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
}

#[derive(Clone, Debug)]
struct HttpObservation {
    value: Value,
    sanitized: Value,
    response_bytes: usize,
    response_sha256: String,
    elapsed_ms: u64,
    usage: TokenUsage,
    system_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TrialRecord {
    sequence: usize,
    arm: McpArm,
    fixture_case: LifecycleFixtureCase,
    fixture_id: String,
    phase: String,
    first_for_arm: bool,
    status: String,
    fault: Option<EvidenceFault>,
    total_elapsed_ms: u64,
    first_request: Value,
    first_request_bytes: usize,
    first_request_sha256: String,
    first_response: Option<Value>,
    first_response_bytes: Option<usize>,
    first_response_sha256: Option<String>,
    first_elapsed_ms: Option<u64>,
    first_usage: Option<TokenUsage>,
    first_system_fingerprint: Option<String>,
    tool_call: Option<Value>,
    tool_call_valid: bool,
    bridge_observation: Option<BridgeObservation>,
    exact_response_equality: bool,
    tool_projection: Option<LifecycleProjection>,
    second_request: Option<Value>,
    second_request_bytes: Option<usize>,
    second_request_sha256: Option<String>,
    second_response: Option<Value>,
    second_response_bytes: Option<usize>,
    second_response_sha256: Option<String>,
    second_elapsed_ms: Option<u64>,
    second_usage: Option<TokenUsage>,
    second_system_fingerprint: Option<String>,
    imported_projection: Option<LifecycleProjection>,
    import_valid: bool,
    private_reasoning_recorded: bool,
}

impl TrialRecord {
    fn new(
        sequence: usize,
        arm: McpArm,
        fixture: &GovernedLifecycleFixture,
        phase: &str,
        first_for_arm: bool,
        first_request: Value,
    ) -> Result<Self, EvidenceFault> {
        let first_request_encoded =
            encode_bounded(&first_request, MAX_HTTP_BODY_BYTES, "first_request")?;
        Ok(Self {
            sequence,
            arm,
            fixture_case: fixture.case,
            fixture_id: fixture.fixture_id.to_owned(),
            phase: phase.to_owned(),
            first_for_arm,
            status: "failed".to_owned(),
            fault: None,
            total_elapsed_ms: 0,
            first_request,
            first_request_bytes: first_request_encoded.len(),
            first_request_sha256: sha256_hex(&first_request_encoded),
            first_response: None,
            first_response_bytes: None,
            first_response_sha256: None,
            first_elapsed_ms: None,
            first_usage: None,
            first_system_fingerprint: None,
            tool_call: None,
            tool_call_valid: false,
            bridge_observation: None,
            exact_response_equality: false,
            tool_projection: None,
            second_request: None,
            second_request_bytes: None,
            second_request_sha256: None,
            second_response: None,
            second_response_bytes: None,
            second_response_sha256: None,
            second_elapsed_ms: None,
            second_usage: None,
            second_system_fingerprint: None,
            imported_projection: None,
            import_valid: false,
            private_reasoning_recorded: false,
        })
    }

    fn fail(&mut self, fault: impl Into<EvidenceFault>, started: Instant) {
        self.fault = Some(fault.into());
        self.total_elapsed_ms = elapsed_ms(started);
    }

    fn record_first(&mut self, observation: &HttpObservation) {
        self.first_response = Some(observation.sanitized.clone());
        self.first_response_bytes = Some(observation.response_bytes);
        self.first_response_sha256 = Some(observation.response_sha256.clone());
        self.first_elapsed_ms = Some(observation.elapsed_ms);
        self.first_usage = Some(observation.usage.clone());
        self.first_system_fingerprint = observation.system_fingerprint.clone();
    }

    fn record_second_request(&mut self, request: Value) -> Result<(), EvidenceFault> {
        let encoded = encode_bounded(&request, MAX_HTTP_BODY_BYTES, "second_request")?;
        self.second_request_bytes = Some(encoded.len());
        self.second_request_sha256 = Some(sha256_hex(&encoded));
        self.second_request = Some(request);
        Ok(())
    }

    fn record_second(&mut self, observation: &HttpObservation) {
        self.second_response = Some(observation.sanitized.clone());
        self.second_response_bytes = Some(observation.response_bytes);
        self.second_response_sha256 = Some(observation.response_sha256.clone());
        self.second_elapsed_ms = Some(observation.elapsed_ms);
        self.second_usage = Some(observation.usage.clone());
        self.second_system_fingerprint = observation.system_fingerprint.clone();
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ArmSummary {
    arm: McpArm,
    first_call_count: usize,
    first_call_completed: usize,
    first_call_total_elapsed_ms: u64,
    measured_count: usize,
    measured_completed: usize,
    measured_total_elapsed_ms: u64,
    measured_mean_elapsed_ms: Option<u64>,
    measured_tool_argument_bytes: usize,
    measured_tool_response_bytes: usize,
    measured_prompt_tokens: u64,
    measured_completion_tokens: u64,
    exact_response_count: usize,
    valid_import_count: usize,
}

enum ArmRef<'a> {
    Stateless(&'a StatelessSession),
    Custody(&'a CustodySession),
}

impl ArmRef<'_> {
    fn arm(&self) -> McpArm {
        match self {
            Self::Stateless(_) => McpArm::Stateless,
            Self::Custody(_) => McpArm::VolatileCustody,
        }
    }

    async fn validate(
        &self,
        fixture: &GovernedLifecycleFixture,
    ) -> Result<BridgeObservation, EvidenceFault> {
        match self {
            Self::Stateless(session) => session.validate(fixture).await,
            Self::Custody(session) => session.validate(fixture).await,
        }
        .map_err(|error| EvidenceFault::new("mcp_bridge_fault", error))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration_fault: {error}");
            return ExitCode::from(2);
        }
    };
    let started_unix_ms = unix_time_ms();
    let report = run(&config, started_unix_ms).await;
    let status = report
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("internal_fault");
    if let Some(parent) = config.output.parent()
        && let Err(error) = fs::create_dir_all(parent)
    {
        eprintln!(
            "evidence_fault: cannot create {}: {error}",
            parent.display()
        );
        return ExitCode::from(2);
    }
    let encoded = match serde_json::to_vec_pretty(&report) {
        Ok(encoded) if encoded.len() <= MAX_REPORT_BYTES => encoded,
        Ok(encoded) => {
            eprintln!(
                "evidence_fault: report contains {} bytes; maximum is {MAX_REPORT_BYTES}",
                encoded.len()
            );
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("evidence_fault: cannot serialize report: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = fs::write(&config.output, &encoded) {
        eprintln!(
            "evidence_fault: cannot write {}: {error}",
            config.output.display()
        );
        return ExitCode::from(2);
    }
    println!(
        "{status}: {} bytes written to {}",
        encoded.len(),
        config.output.display()
    );
    match status {
        "passed" => ExitCode::SUCCESS,
        "provider_unavailable" | "provider_mismatch" => ExitCode::from(3),
        _ => ExitCode::from(1),
    }
}

async fn run(config: &Config, started_unix_ms: u128) -> Value {
    let fixtures = match load_fixtures() {
        Ok(fixtures) => fixtures,
        Err(fault) => return early_report(config, started_unix_ms, "fixture_refused", fault, None),
    };
    let client = match Client::builder().timeout(config.timeout).build() {
        Ok(client) => client,
        Err(error) => {
            return early_report(
                config,
                started_unix_ms,
                "internal_fault",
                EvidenceFault::new("http_client_fault", error),
                None,
            );
        }
    };
    let preflight = match provider_preflight(&client, config).await {
        Ok(preflight) => preflight,
        Err(fault) => {
            let status = if fault.kind == "provider_mismatch" {
                "provider_mismatch"
            } else {
                "provider_unavailable"
            };
            return early_report(config, started_unix_ms, status, fault, None);
        }
    };

    let stateless = match StatelessSession::open(&config.stateless_mcp_bin, config.timeout).await {
        Ok(session) => session,
        Err(error) => {
            return early_report(
                config,
                started_unix_ms,
                "mcp_unavailable",
                EvidenceFault::new("stateless_mcp_fault", error),
                Some(preflight),
            );
        }
    };
    let mut custody = match CustodySession::open(&config.custody_mcp_bin, config.timeout).await {
        Ok(session) => session,
        Err(error) => {
            let _ = stateless.close().await;
            return early_report(
                config,
                started_unix_ms,
                "mcp_unavailable",
                EvidenceFault::new("custody_mcp_fault", error),
                Some(preflight),
            );
        }
    };
    let mut registrations: Vec<RegistrationObservation> = Vec::new();
    for fixture in fixtures.values() {
        match custody.register(fixture).await {
            Ok(registration) => registrations.push(registration),
            Err(error) => {
                let _ = stateless.close().await;
                let _ = custody.close().await;
                return early_report(
                    config,
                    started_unix_ms,
                    "mcp_refused",
                    EvidenceFault::new("custody_registration_fault", error),
                    Some(preflight),
                );
            }
        }
    }

    let stateless_ref = ArmRef::Stateless(&stateless);
    let custody_ref = ArmRef::Custody(&custody);
    let total_rounds = config.warmups + config.measured_trials;
    let mut first_seen = [false, false];
    let mut sequence = 0;
    let mut trials = Vec::new();
    for round in 0..total_rounds {
        let phase = if round < config.warmups {
            "warmup"
        } else {
            "measured"
        };
        for (case_index, case) in [
            LifecycleFixtureCase::Valid,
            LifecycleFixtureCase::LifecycleRefused,
        ]
        .into_iter()
        .enumerate()
        {
            let order = if (round + case_index) % 2 == 0 {
                [&stateless_ref, &custody_ref]
            } else {
                [&custody_ref, &stateless_ref]
            };
            let fixture = fixtures.get(&case).expect("complete fixture map");
            for arm in order {
                let arm_index = if arm.arm() == McpArm::Stateless { 0 } else { 1 };
                let first_for_arm = !first_seen[arm_index];
                first_seen[arm_index] = true;
                trials.push(
                    run_trial(
                        &client,
                        config,
                        sequence,
                        phase,
                        first_for_arm,
                        arm,
                        fixture,
                    )
                    .await,
                );
                sequence += 1;
            }
        }
    }

    let retained_restart_handle = custody.handle(LifecycleFixtureCase::Valid).cloned();
    let stateless_close = stateless.close().await.err().map(|error| error.to_string());
    let custody_close = custody.close().await.err().map(|error| error.to_string());
    let (restart_trial, restart_passed) = match retained_restart_handle {
        Some(handle) if custody_close.is_none() => run_restart_trial(config, &handle).await,
        Some(_) => (
            json!({
                "status": "incomplete",
                "fault": "original custody process did not close cleanly",
                "excluded_from_steady_state": true
            }),
            false,
        ),
        None => (
            json!({
                "status": "incomplete",
                "fault": "valid fixture handle was not retained",
                "excluded_from_steady_state": true
            }),
            false,
        ),
    };
    let stateless_summary = summarize_arm(McpArm::Stateless, &trials);
    let custody_summary = summarize_arm(McpArm::VolatileCustody, &trials);
    let comparison = compare_arms(&stateless_summary, &custody_summary);
    let passed = trials
        .iter()
        .filter(|trial| trial.phase == "measured")
        .all(|trial| trial.status == "passed")
        && stateless_close.is_none()
        && custody_close.is_none()
        && restart_passed;

    json!({
        "probe": "cantor_live_lifecycle_tool_loop_measurement_p0",
        "contract": "Cantor_Live_Lifecycle_Tool_Loop_Measurement_P0.sop",
        "provider": "llama.cpp",
        "provider_release_expected": PINNED_PROVIDER_RELEASE,
        "provider_system_fingerprint_expected": PINNED_SYSTEM_FINGERPRINT,
        "provider_release_contract_sha256": RELEASE_CONTRACT_SHA256,
        "base_url": config.base_url,
        "model": config.model,
        "expected_model_path": config.expected_model_path,
        "generation_settings": {
            "temperature": 0,
            "checkpoint_one_max_tokens": 128,
            "checkpoint_two_max_tokens": 256,
            "parallel_tool_calls": false,
            "checkpoint_one_tool_choice": "required",
            "checkpoint_two_tool_choice": "none"
        },
        "bounds": {
            "timeout_ms": config.timeout.as_millis(),
            "max_http_body_bytes": MAX_HTTP_BODY_BYTES,
            "max_report_bytes": MAX_REPORT_BYTES,
            "measured_trials_per_arm_case": config.measured_trials,
            "warmups_per_arm_case": config.warmups
        },
        "started_unix_ms": started_unix_ms,
        "finished_unix_ms": unix_time_ms(),
        "status": if passed { "passed" } else { "failed" },
        "preflight": preflight,
        "custody_registrations_outside_measured_steady_state": registrations,
        "subprocess_shutdown": {
            "stateless_fault": stateless_close,
            "custody_fault": custody_close
        },
        "restart_trial": restart_trial,
        "summaries": [stateless_summary, custody_summary],
        "comparison": comparison,
        "private_reasoning_recorded": false,
        "hardware": {
            "target_os": env::consts::OS,
            "target_arch": env::consts::ARCH,
            "logical_parallelism": std::thread::available_parallelism().ok().map(std::num::NonZero::get),
            "gpu_identity_observed": null
        },
        "trials": trials
    })
}

async fn run_restart_trial(
    config: &Config,
    retained_handle: &cantor_core::NativeLifecycleCustodyHandle,
) -> (Value, bool) {
    let started = Instant::now();
    let restarted = match CustodySession::open(&config.custody_mcp_bin, config.timeout).await {
        Ok(restarted) => restarted,
        Err(error) => {
            return (
                json!({
                    "status": "failed",
                    "fault": EvidenceFault::new("restart_process_fault", error),
                    "elapsed_ms": elapsed_ms(started),
                    "excluded_from_steady_state": true
                }),
                false,
            );
        }
    };
    let response = match restarted.validate_raw_handle(retained_handle).await {
        Ok(response) => response,
        Err(error) => {
            let _ = restarted.close().await;
            return (
                json!({
                    "status": "failed",
                    "fault": EvidenceFault::new("restart_validation_fault", error),
                    "elapsed_ms": elapsed_ms(started),
                    "excluded_from_steady_state": true
                }),
                false,
            );
        }
    };
    let close_fault = restarted.close().await.err().map(|error| error.to_string());
    let passed = response.status == CustodyStatus::Refused
        && response.lifecycle_response.is_none()
        && close_fault.is_none();
    (
        json!({
            "status": if passed { "passed" } else { "failed" },
            "old_handle_refused": response.status == CustodyStatus::Refused,
            "response": response,
            "shutdown_fault": close_fault,
            "elapsed_ms": elapsed_ms(started),
            "excluded_from_steady_state": true,
            "persistence_claimed": false
        }),
        passed,
    )
}

async fn run_trial(
    client: &Client,
    config: &Config,
    sequence: usize,
    phase: &str,
    first_for_arm: bool,
    arm: &ArmRef<'_>,
    fixture: &GovernedLifecycleFixture,
) -> TrialRecord {
    let started = Instant::now();
    let request = first_request(&config.model, fixture.fixture_id);
    let mut record = match TrialRecord::new(
        sequence,
        arm.arm(),
        fixture,
        phase,
        first_for_arm,
        request.clone(),
    ) {
        Ok(record) => record,
        Err(fault) => {
            return failed_record(sequence, arm.arm(), fixture, phase, first_for_arm, fault);
        }
    };
    let first = match post_json(client, &chat_url(config), &request).await {
        Ok(first) => first,
        Err(fault) => {
            record.fail(fault, started);
            return record;
        }
    };
    record.record_first(&first);
    let invocation = match extract_tool_invocation(&first.value, fixture.fixture_id) {
        Ok(invocation) => invocation,
        Err(fault) => {
            record.fail(fault, started);
            return record;
        }
    };
    record.tool_call = Some(invocation.tool_call.clone());
    record.tool_call_valid = true;
    let bridge = match arm.validate(fixture).await {
        Ok(bridge) => bridge,
        Err(fault) => {
            record.fail(fault, started);
            return record;
        }
    };
    record.exact_response_equality = bridge.exact_direct_response;
    let projection = match lifecycle_projection(fixture, &bridge.lifecycle_response) {
        Ok(projection) => projection,
        Err(fault) => {
            record.bridge_observation = Some(bridge);
            record.fail(fault, started);
            return record;
        }
    };
    record.bridge_observation = Some(bridge);
    record.tool_projection = Some(projection.clone());
    let second = match second_request(
        &config.model,
        fixture.fixture_id,
        &invocation,
        &invocation.call_id,
        &projection,
    ) {
        Ok(second) => second,
        Err(fault) => {
            record.fail(fault, started);
            return record;
        }
    };
    if let Err(fault) = record.record_second_request(second.clone()) {
        record.fail(fault, started);
        return record;
    }
    let second_observation = match post_json(client, &chat_url(config), &second).await {
        Ok(second) => second,
        Err(fault) => {
            record.fail(fault, started);
            return record;
        }
    };
    record.record_second(&second_observation);
    let imported = match extract_imported_projection(&second_observation.value, &projection) {
        Ok(imported) => imported,
        Err(fault) => {
            record.fail(fault, started);
            return record;
        }
    };
    record.imported_projection = Some(imported);
    record.import_valid = true;
    record.status = "passed".to_owned();
    record.total_elapsed_ms = elapsed_ms(started);
    record
}

fn failed_record(
    sequence: usize,
    arm: McpArm,
    fixture: &GovernedLifecycleFixture,
    phase: &str,
    first_for_arm: bool,
    fault: EvidenceFault,
) -> TrialRecord {
    TrialRecord {
        sequence,
        arm,
        fixture_case: fixture.case,
        fixture_id: fixture.fixture_id.to_owned(),
        phase: phase.to_owned(),
        first_for_arm,
        status: "failed".to_owned(),
        fault: Some(fault),
        total_elapsed_ms: 0,
        first_request: Value::Null,
        first_request_bytes: 0,
        first_request_sha256: sha256_hex(&[]),
        first_response: None,
        first_response_bytes: None,
        first_response_sha256: None,
        first_elapsed_ms: None,
        first_usage: None,
        first_system_fingerprint: None,
        tool_call: None,
        tool_call_valid: false,
        bridge_observation: None,
        exact_response_equality: false,
        tool_projection: None,
        second_request: None,
        second_request_bytes: None,
        second_request_sha256: None,
        second_response: None,
        second_response_bytes: None,
        second_response_sha256: None,
        second_elapsed_ms: None,
        second_usage: None,
        second_system_fingerprint: None,
        imported_projection: None,
        import_valid: false,
        private_reasoning_recorded: false,
    }
}

fn load_fixtures() -> Result<BTreeMap<LifecycleFixtureCase, GovernedLifecycleFixture>, EvidenceFault>
{
    let mut fixtures = BTreeMap::new();
    for case in [
        LifecycleFixtureCase::Valid,
        LifecycleFixtureCase::LifecycleRefused,
    ] {
        let fixture = GovernedLifecycleFixture::load(case)
            .map_err(|error| EvidenceFault::new("fixture_refused", error))?;
        fixtures.insert(case, fixture);
    }
    Ok(fixtures)
}

async fn provider_preflight(client: &Client, config: &Config) -> Result<Value, EvidenceFault> {
    let props_url = format!(
        "{}/props",
        config
            .base_url
            .strip_suffix("/v1")
            .unwrap_or(&config.base_url)
    );
    let props = get_json(client, &props_url).await?;
    let models = get_json(client, &format!("{}/models", config.base_url)).await?;
    let model_path = props
        .value
        .pointer("/default_generation_settings/model")
        .or_else(|| props.value.get("model_path"))
        .and_then(Value::as_str)
        .ok_or_else(|| EvidenceFault::new("provider_mismatch", "missing observed model path"))?;
    if normalize_path(model_path) != normalize_path(&config.expected_model_path) {
        return Err(EvidenceFault::new(
            "provider_mismatch",
            format!(
                "expected model path {:?}, observed {:?}",
                config.expected_model_path, model_path
            ),
        ));
    }
    let model_visible = models
        .value
        .get("data")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("id").and_then(Value::as_str) == Some(config.model.as_str()))
        });
    if !model_visible {
        return Err(EvidenceFault::new(
            "provider_mismatch",
            format!("pinned model alias {:?} absent from /models", config.model),
        ));
    }
    let chat_template_present = props
        .value
        .get("chat_template")
        .and_then(Value::as_str)
        .is_some_and(|template| !template.is_empty());
    if !chat_template_present {
        return Err(EvidenceFault::new(
            "provider_mismatch",
            "provider has no observed chat template",
        ));
    }
    Ok(json!({
        "status": "passed",
        "props_endpoint": props_url,
        "props_elapsed_ms": props.elapsed_ms,
        "props_response_bytes": props.response_bytes,
        "props_response_sha256": props.response_sha256,
        "models_elapsed_ms": models.elapsed_ms,
        "models_response_bytes": models.response_bytes,
        "models_response_sha256": models.response_sha256,
        "observed_model_path": model_path,
        "observed_model_alias": config.model,
        "chat_template_present": true,
        "total_slots": props.value.get("total_slots").cloned(),
        "release_contract_digest_verified": true,
        "provider_release_runtime_confirmation": "each completion must report exact system_fingerprint b10181-caa596ab3"
    }))
}

async fn post_json(
    client: &Client,
    url: &str,
    body: &Value,
) -> Result<HttpObservation, EvidenceFault> {
    encode_bounded(body, MAX_HTTP_BODY_BYTES, "http_request")?;
    let started = Instant::now();
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|error| EvidenceFault::new("provider_fault", error))?;
    let status = response.status();
    let response_bytes = bounded_body(response).await?;
    let elapsed_ms = elapsed_ms(started);
    if !status.is_success() {
        return Err(EvidenceFault::new(
            "provider_fault",
            format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(&response_bytes)
            ),
        ));
    }
    let value: Value = serde_json::from_slice(&response_bytes)
        .map_err(|error| EvidenceFault::new("provider_fault", error))?;
    let fingerprint = value
        .get("system_fingerprint")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if fingerprint.as_deref() != Some(PINNED_SYSTEM_FINGERPRINT) {
        return Err(EvidenceFault::new(
            "provider_mismatch",
            format!(
                "expected system_fingerprint {PINNED_SYSTEM_FINGERPRINT:?}, received {fingerprint:?}"
            ),
        ));
    }
    if value.get("model").and_then(Value::as_str) != Some(PINNED_MODEL) {
        return Err(EvidenceFault::new(
            "provider_mismatch",
            format!("completion model field differs from {PINNED_MODEL}"),
        ));
    }
    Ok(HttpObservation {
        sanitized: sanitize_response(&value),
        usage: token_usage(&value),
        system_fingerprint: fingerprint,
        value,
        response_bytes: response_bytes.len(),
        response_sha256: sha256_hex(&response_bytes),
        elapsed_ms,
    })
}

async fn get_json(client: &Client, url: &str) -> Result<HttpObservation, EvidenceFault> {
    let started = Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| EvidenceFault::new("provider_unavailable", error))?;
    let status = response.status();
    let response_bytes = bounded_body(response).await?;
    let elapsed_ms = elapsed_ms(started);
    if !status.is_success() {
        return Err(EvidenceFault::new(
            "provider_unavailable",
            format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(&response_bytes)
            ),
        ));
    }
    let value: Value = serde_json::from_slice(&response_bytes)
        .map_err(|error| EvidenceFault::new("provider_unavailable", error))?;
    Ok(HttpObservation {
        sanitized: sanitize_response(&value),
        usage: TokenUsage::default(),
        system_fingerprint: None,
        value,
        response_bytes: response_bytes.len(),
        response_sha256: sha256_hex(&response_bytes),
        elapsed_ms,
    })
}

async fn bounded_body(mut response: Response) -> Result<Vec<u8>, EvidenceFault> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_BODY_BYTES as u64)
    {
        return Err(EvidenceFault::new(
            "response_bound_fault",
            "Content-Length exceeds the response ceiling",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| EvidenceFault::new("provider_fault", error))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_BODY_BYTES {
            return Err(EvidenceFault::new(
                "response_bound_fault",
                format!("stream exceeds {MAX_HTTP_BODY_BYTES} bytes"),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn summarize_arm(arm: McpArm, trials: &[TrialRecord]) -> ArmSummary {
    let arm_trials: Vec<_> = trials.iter().filter(|trial| trial.arm == arm).collect();
    let first: Vec<_> = arm_trials
        .iter()
        .copied()
        .filter(|trial| trial.first_for_arm)
        .collect();
    let measured: Vec<_> = arm_trials
        .iter()
        .copied()
        .filter(|trial| trial.phase == "measured")
        .collect();
    let measured_total_elapsed_ms = measured.iter().map(|trial| trial.total_elapsed_ms).sum();
    let measured_completed = measured
        .iter()
        .filter(|trial| trial.status == "passed")
        .count();
    let token_sum = |selector: fn(&TrialRecord) -> Option<&TokenUsage>,
                     field: fn(&TokenUsage) -> Option<u64>| {
        measured
            .iter()
            .filter_map(|trial| selector(trial))
            .filter_map(field)
            .sum::<u64>()
    };
    ArmSummary {
        arm,
        first_call_count: first.len(),
        first_call_completed: first
            .iter()
            .filter(|trial| trial.status == "passed")
            .count(),
        first_call_total_elapsed_ms: first.iter().map(|trial| trial.total_elapsed_ms).sum(),
        measured_count: measured.len(),
        measured_completed,
        measured_total_elapsed_ms,
        measured_mean_elapsed_ms: (!measured.is_empty())
            .then_some(measured_total_elapsed_ms / measured.len() as u64),
        measured_tool_argument_bytes: measured
            .iter()
            .filter_map(|trial| trial.bridge_observation.as_ref())
            .map(|observation| observation.argument_bytes)
            .sum(),
        measured_tool_response_bytes: measured
            .iter()
            .filter_map(|trial| trial.bridge_observation.as_ref())
            .map(|observation| observation.structured_response_bytes)
            .sum(),
        measured_prompt_tokens: token_sum(
            |trial| trial.first_usage.as_ref(),
            |usage| usage.prompt_tokens,
        ) + token_sum(
            |trial| trial.second_usage.as_ref(),
            |usage| usage.prompt_tokens,
        ),
        measured_completion_tokens: token_sum(
            |trial| trial.first_usage.as_ref(),
            |usage| usage.completion_tokens,
        ) + token_sum(
            |trial| trial.second_usage.as_ref(),
            |usage| usage.completion_tokens,
        ),
        exact_response_count: measured
            .iter()
            .filter(|trial| trial.exact_response_equality)
            .count(),
        valid_import_count: measured.iter().filter(|trial| trial.import_valid).count(),
    }
}

fn compare_arms(stateless: &ArmSummary, custody: &ArmSummary) -> Value {
    let stateless_bytes = stateless.measured_tool_argument_bytes;
    let custody_bytes = custody.measured_tool_argument_bytes;
    let compression_basis_points = if stateless_bytes == 0 {
        None
    } else {
        Some(
            custody_bytes
                .saturating_mul(10_000)
                .checked_div(stateless_bytes)
                .unwrap_or(0),
        )
    };
    json!({
        "stateless_transport_argument_bytes": stateless_bytes,
        "custody_transport_argument_bytes": custody_bytes,
        "transport_bytes_saved": stateless_bytes.saturating_sub(custody_bytes),
        "custody_to_stateless_argument_basis_points": compression_basis_points,
        "model_prompt_token_delta_custody_minus_stateless": signed_difference(
            custody.measured_prompt_tokens,
            stateless.measured_prompt_tokens
        ),
        "model_completion_token_delta_custody_minus_stateless": signed_difference(
            custody.measured_completion_tokens,
            stateless.measured_completion_tokens
        ),
        "mean_total_latency_delta_ms_custody_minus_stateless": match (
            custody.measured_mean_elapsed_ms,
            stateless.measured_mean_elapsed_ms
        ) {
            (Some(custody), Some(stateless)) => Some(signed_difference(custody, stateless)),
            _ => None
        }
    })
}

fn signed_difference(left: u64, right: u64) -> i64 {
    i64::try_from(i128::from(left) - i128::from(right)).unwrap_or(if left >= right {
        i64::MAX
    } else {
        i64::MIN
    })
}

fn token_usage(value: &Value) -> TokenUsage {
    TokenUsage {
        prompt_tokens: value
            .pointer("/usage/prompt_tokens")
            .and_then(Value::as_u64),
        completion_tokens: value
            .pointer("/usage/completion_tokens")
            .and_then(Value::as_u64),
        total_tokens: value.pointer("/usage/total_tokens").and_then(Value::as_u64),
    }
}

fn early_report(
    config: &Config,
    started_unix_ms: u128,
    status: &str,
    fault: EvidenceFault,
    preflight: Option<Value>,
) -> Value {
    json!({
        "probe": "cantor_live_lifecycle_tool_loop_measurement_p0",
        "contract": "Cantor_Live_Lifecycle_Tool_Loop_Measurement_P0.sop",
        "provider": "llama.cpp",
        "provider_release_expected": PINNED_PROVIDER_RELEASE,
        "provider_system_fingerprint_expected": PINNED_SYSTEM_FINGERPRINT,
        "provider_release_contract_sha256": RELEASE_CONTRACT_SHA256,
        "base_url": config.base_url,
        "model": config.model,
        "started_unix_ms": started_unix_ms,
        "finished_unix_ms": unix_time_ms(),
        "status": status,
        "fault": fault,
        "preflight": preflight,
        "private_reasoning_recorded": false,
        "custody_registrations_outside_measured_steady_state": [],
        "trials": []
    })
}

fn encode_bounded(value: &Value, maximum: usize, field: &str) -> Result<Vec<u8>, EvidenceFault> {
    let encoded =
        serde_json::to_vec(value).map_err(|error| EvidenceFault::new("encoding_fault", error))?;
    if encoded.len() > maximum {
        return Err(EvidenceFault::new(
            "request_bound_fault",
            format!(
                "{field} contains {} bytes; maximum is {maximum}",
                encoded.len()
            ),
        ));
    }
    Ok(encoded)
}

fn chat_url(config: &Config) -> String {
    format!("{}/chat/completions", config.base_url)
}

fn normalize_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_lowercase()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_bound_configuration_are_enforced() {
        let config = Config {
            base_url: "https://example.com/v1".to_owned(),
            model: PINNED_MODEL.to_owned(),
            expected_model_path: PINNED_MODEL_PATH.to_owned(),
            stateless_mcp_bin: PathBuf::from("missing-a"),
            custody_mcp_bin: PathBuf::from("missing-b"),
            output: PathBuf::from("unused"),
            timeout: Duration::from_secs(1),
            measured_trials: 1,
            warmups: 0,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn release_contract_is_digest_bound() {
        assert_eq!(sha256_hex(RELEASE_CONTRACT_BYTES), RELEASE_CONTRACT_SHA256);
        assert_eq!(RELEASE_CONTRACT_BYTES.len(), 1_022);
    }

    #[test]
    fn arm_comparison_reports_transport_and_model_context_separately() {
        let stateless = ArmSummary {
            arm: McpArm::Stateless,
            first_call_count: 1,
            first_call_completed: 1,
            first_call_total_elapsed_ms: 10,
            measured_count: 2,
            measured_completed: 2,
            measured_total_elapsed_ms: 20,
            measured_mean_elapsed_ms: Some(10),
            measured_tool_argument_bytes: 1_000,
            measured_tool_response_bytes: 100,
            measured_prompt_tokens: 80,
            measured_completion_tokens: 20,
            exact_response_count: 2,
            valid_import_count: 2,
        };
        let mut custody = stateless.clone();
        custody.arm = McpArm::VolatileCustody;
        custody.measured_tool_argument_bytes = 100;
        let comparison = compare_arms(&stateless, &custody);
        assert_eq!(comparison["transport_bytes_saved"], 900);
        assert_eq!(
            comparison["custody_to_stateless_argument_basis_points"],
            1_000
        );
        assert_eq!(
            comparison["model_prompt_token_delta_custody_minus_stateless"],
            0
        );
    }
}
