#![forbid(unsafe_code)]

use std::{
    env,
    error::Error,
    fmt::{self, Display},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use cantor_attention_mcp::{SERVER_INSTRUCTIONS, TOOL_NAME};
use cantor_reflection_loop::{
    CONTROL_CASE, CaseDefinition, CaseKind, FinalOutput, FlowEvent, FlowState, REPORT_PROFILE,
    TRACE_PROFILE, admit_tool_result, contract, control_request, extract_control_output,
    extract_final_output, extract_tool_call, first_request, inspect_report, reflection_request,
    routed_cases, sanitize, verify_report,
};
use reqwest::{Client, Url};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, JsonObject},
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug)]
struct Config {
    base_url: String,
    mcp_program: PathBuf,
    mcp_config: PathBuf,
    output: PathBuf,
    timeout: Duration,
}

impl Config {
    fn parse(raw_arguments: Vec<String>) -> Result<Self, AnyError> {
        let mut base_url = "http://127.0.0.1:8081/v1".to_owned();
        let mut mcp_program = None;
        let mut mcp_config = None;
        let mut output = PathBuf::from("cantor_reflection_loop_report.json");
        let mut timeout = Duration::from_secs(180);
        let mut arguments = raw_arguments.into_iter();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--base-url" => base_url = required(&mut arguments, "--base-url")?,
                "--mcp-program" => {
                    mcp_program = Some(PathBuf::from(required(&mut arguments, "--mcp-program")?))
                }
                "--mcp-config" => {
                    mcp_config = Some(PathBuf::from(required(&mut arguments, "--mcp-config")?))
                }
                "--output" => output = PathBuf::from(required(&mut arguments, "--output")?),
                "--timeout-seconds" => {
                    let value = required(&mut arguments, "--timeout-seconds")?;
                    timeout = Duration::from_secs(value.parse()?);
                }
                "--case" => {
                    let value = required(&mut arguments, "--case")?;
                    if value != "all" {
                        return Err(
                            "P0 only permits the complete positive-refusal-control campaign".into(),
                        );
                    }
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                value => return Err(format!("unknown argument: {value}").into()),
            }
        }
        let mcp_program = mcp_program.ok_or("--mcp-program is required")?;
        let mcp_config = mcp_config.ok_or("--mcp-config is required")?;
        if timeout.is_zero() || timeout > Duration::from_secs(600) {
            return Err("timeout must be within 1..=600 seconds".into());
        }
        if output.exists() {
            return Err(format!("output already exists: {}", output.display()).into());
        }
        Ok(Self {
            base_url: validate_base_url(&base_url)?,
            mcp_program,
            mcp_config,
            output,
            timeout,
        })
    }
}

fn validate_base_url(candidate: &str) -> Result<String, AnyError> {
    let parsed = Url::parse(candidate)?;
    let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if parsed.scheme() != "http"
        || !loopback
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path().trim_end_matches('/') != "/v1"
    {
        return Err("base URL must be an unauthenticated loopback HTTP /v1 root".into());
    }
    Ok(candidate.trim_end_matches('/').to_owned())
}

fn required(arguments: &mut impl Iterator<Item = String>, name: &str) -> Result<String, AnyError> {
    arguments
        .next()
        .ok_or_else(|| format!("{name} requires a value").into())
}

fn print_help() {
    println!(
        "cantor-reflection-loop\n\
         \n\
         Runs the bounded llama.cpp -> Cantor MCP -> llama.cpp P0 loop.\n\
         \n\
         Offline verification:\n\
           cantor-reflection-loop verify --report PATH\n\
         Compact inspection:\n\
           cantor-reflection-loop inspect --report PATH\n\
         Machine-readable contract:\n\
           cantor-reflection-loop contract\n\
         \n\
         Required:\n\
           --mcp-program PATH     cantor-attention-mcp executable\n\
           --mcp-config PATH      pinned adapter configuration\n\
         Options:\n\
           --base-url URL         llama.cpp OpenAI API root (default: http://127.0.0.1:8081/v1)\n\
           --case all             accepted compatibility spelling; the complete campaign is mandatory\n\
           --output PATH          report JSON path\n\
           --timeout-seconds N    provider timeout within 1..=600 (default: 180)"
    );
}

#[derive(Debug)]
struct LoopFault {
    code: &'static str,
    detail: String,
}

impl LoopFault {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl Display for LoopFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for LoopFault {}

#[derive(Debug, Serialize)]
struct CaseTrace {
    profile: &'static str,
    trace_id: String,
    case_id: String,
    expected_case_kind: CaseKind,
    final_state: FlowState,
    status: String,
    events: Vec<FlowEvent>,
    first_request: Value,
    first_response: Option<Value>,
    tool_call: Option<Value>,
    tool_result: Option<Value>,
    reflection_request: Option<Value>,
    reflection_response: Option<Value>,
    final_output: Option<FinalOutput>,
    fault: Option<FaultRecord>,
    elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
struct FaultRecord {
    code: String,
    detail: String,
}

impl CaseTrace {
    fn new(case: &CaseDefinition, first_request: Value) -> Self {
        let mut result = Self {
            profile: TRACE_PROFILE,
            trace_id: new_trace_id(),
            case_id: case.case_id.to_owned(),
            expected_case_kind: case.kind,
            final_state: FlowState::Created,
            status: "running".to_owned(),
            events: Vec::new(),
            first_request,
            first_response: None,
            tool_call: None,
            tool_result: None,
            reflection_request: None,
            reflection_response: None,
            final_output: None,
            fault: None,
            elapsed_ms: 0,
        };
        result.transition(FlowState::Created, "case trace created");
        result
    }

    fn transition(&mut self, state: FlowState, detail: impl Into<String>) {
        self.final_state = state;
        self.events.push(FlowEvent {
            sequence: self.events.len(),
            state,
            detail: detail.into(),
        });
    }

    fn pass(&mut self, state: FlowState, started: Instant) {
        self.transition(state, "case acceptance contract satisfied");
        self.status = "passed".to_owned();
        self.elapsed_ms = started.elapsed().as_millis();
    }

    fn fail(&mut self, fault: LoopFault, started: Instant) {
        self.transition(
            FlowState::Failed,
            format!("{}: {}", fault.code, fault.detail),
        );
        self.status = "failed".to_owned();
        self.fault = Some(FaultRecord {
            code: fault.code.to_owned(),
            detail: fault.detail,
        });
        self.elapsed_ms = started.elapsed().as_millis();
    }
}

#[derive(Debug, Serialize)]
struct RunReport {
    profile: &'static str,
    contract: &'static str,
    status: String,
    started_unix_ms: u128,
    finished_unix_ms: u128,
    base_url: String,
    model: String,
    mcp_program: String,
    mcp_program_sha256: String,
    mcp_program_sha256_after: String,
    mcp_config: String,
    mcp_config_sha256: String,
    mcp_config_sha256_after: String,
    dependency_identity_stable: bool,
    runner: String,
    runner_sha256: String,
    private_reasoning_recorded: bool,
    cases: Vec<CaseTrace>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.first().map(String::as_str) == Some("verify") {
        return verify_command(&arguments[1..]);
    }
    if arguments.first().map(String::as_str) == Some("inspect") {
        return inspect_command(&arguments[1..]);
    }
    if arguments.first().map(String::as_str) == Some("contract") {
        if arguments.len() != 1 {
            eprintln!("configuration_fault: usage: cantor-reflection-loop contract");
            return ExitCode::from(2);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&contract())
                .expect("ReflectionLoopContract always serializes")
        );
        return ExitCode::SUCCESS;
    }
    let config = match Config::parse(arguments) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration_fault: {error}");
            return ExitCode::from(2);
        }
    };
    match run(config).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("run_fault: {error}");
            ExitCode::from(2)
        }
    }
}

fn verify_command(arguments: &[String]) -> ExitCode {
    if arguments.len() != 2 || arguments[0] != "--report" {
        eprintln!("configuration_fault: usage: cantor-reflection-loop verify --report PATH");
        return ExitCode::from(2);
    }
    let path = Path::new(&arguments[1]);
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("verification_input_fault: {}: {error}", path.display());
            return ExitCode::from(2);
        }
    };
    let report: Value = match serde_json::from_slice(&bytes) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("verification_input_fault: invalid JSON: {error}");
            return ExitCode::from(2);
        }
    };
    match verify_report(&report) {
        Ok(verification) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&verification)
                    .expect("ReportVerification always serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("verification_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn inspect_command(arguments: &[String]) -> ExitCode {
    if arguments.len() != 2 || arguments[0] != "--report" {
        eprintln!("configuration_fault: usage: cantor-reflection-loop inspect --report PATH");
        return ExitCode::from(2);
    }
    let path = Path::new(&arguments[1]);
    let report = match fs::read(path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
        }) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("inspection_input_fault: {}: {error}", path.display());
            return ExitCode::from(2);
        }
    };
    match inspect_report(&report) {
        Ok(inspection) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&inspection)
                    .expect("ReportInspection always serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("inspection_fault: {error}");
            ExitCode::from(1)
        }
    }
}

async fn run(config: Config) -> Result<bool, AnyError> {
    let started_unix_ms = unix_time_ms();
    let mcp_program = canonical_file(&config.mcp_program, "MCP program")?;
    let mcp_config = canonical_file(&config.mcp_config, "MCP config")?;
    let mcp_program_sha256 = sha256_file(&mcp_program)?;
    let mcp_config_sha256 = sha256_file(&mcp_config)?;
    let runner = canonical_file(&env::current_exe()?, "reflection-loop executable")?;
    let runner_sha256 = sha256_file(&runner)?;
    let client = Client::builder().timeout(config.timeout).build()?;
    health_check(&client, &config.base_url).await?;
    let model = discover_model(&client, &config.base_url).await?;
    let mut cases = Vec::new();
    cases.push(
        run_routed_case(
            &client,
            &config.base_url,
            &model,
            &mcp_program,
            &mcp_config,
            &routed_cases()[0],
        )
        .await,
    );
    cases.push(
        run_routed_case(
            &client,
            &config.base_url,
            &model,
            &mcp_program,
            &mcp_config,
            &routed_cases()[1],
        )
        .await,
    );
    cases.push(run_control_case(&client, &config.base_url, &model).await);
    let mcp_program_sha256_after = sha256_file(&mcp_program)?;
    let mcp_config_sha256_after = sha256_file(&mcp_config)?;
    let dependency_identity_stable = mcp_program_sha256 == mcp_program_sha256_after
        && mcp_config_sha256 == mcp_config_sha256_after;
    let passed = cases.iter().all(|case| case.status == "passed") && dependency_identity_stable;
    let report = RunReport {
        profile: REPORT_PROFILE,
        contract: "Cantor_Prototype_Graduation_And_Reflection_Loop_P0.sop",
        status: if passed { "passed" } else { "failed" }.to_owned(),
        started_unix_ms,
        finished_unix_ms: unix_time_ms(),
        base_url: config.base_url,
        model,
        mcp_program: mcp_program.display().to_string(),
        mcp_program_sha256,
        mcp_program_sha256_after,
        mcp_config: mcp_config.display().to_string(),
        mcp_config_sha256,
        mcp_config_sha256_after,
        dependency_identity_stable,
        runner: runner.display().to_string(),
        runner_sha256,
        private_reasoning_recorded: false,
        cases,
    };
    if let Some(parent) = config.output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    write_json_new(&config.output, &report)?;
    println!(
        "{}: sanitized report written to {}",
        if passed { "PASS" } else { "FAIL" },
        config.output.display()
    );
    Ok(passed)
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), AnyError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

async fn run_routed_case(
    client: &Client,
    base_url: &str,
    model: &str,
    mcp_program: &Path,
    mcp_config: &Path,
    case: &CaseDefinition,
) -> CaseTrace {
    let started = Instant::now();
    let request = first_request(model, case);
    let mut trace = CaseTrace::new(case, request.clone());
    trace.transition(
        FlowState::FirstInferenceRequested,
        "submitted one required-tool provider request",
    );
    let response = match post_chat(client, base_url, &request).await {
        Ok(response) => response,
        Err(fault) => {
            trace.fail(fault, started);
            return trace;
        }
    };
    trace.first_response = Some(sanitize(&response));
    trace.transition(
        FlowState::ToolCallReceived,
        "provider returned first-pass message",
    );
    let call = match extract_tool_call(&response, case) {
        Ok(call) => call,
        Err(detail) => {
            trace.fail(LoopFault::new("tool_call_fault", detail), started);
            return trace;
        }
    };
    trace.tool_call = Some(call.call.clone());
    trace.transition(
        FlowState::ToolCallValidated,
        "exact name count and closed arguments admitted",
    );
    let structured = match invoke_mcp(mcp_program, mcp_config, &call.arguments).await {
        Ok(result) => result,
        Err(fault) => {
            trace.fail(fault, started);
            return trace;
        }
    };
    trace.tool_result = Some(structured.clone());
    trace.transition(
        FlowState::ToolResultReceived,
        "structured MCP result received and server process closed",
    );
    let observation = match admit_tool_result(&structured, case) {
        Ok(observation) => observation,
        Err(detail) => {
            trace.fail(LoopFault::new("tool_result_fault", detail), started);
            return trace;
        }
    };
    let second_request = reflection_request(model, case, &call, &structured, &observation);
    trace.reflection_request = Some(second_request.clone());
    trace.transition(
        FlowState::ReflectionRequested,
        "submitted separate provider request with exact admitted tool result",
    );
    let second_response = match post_chat(client, base_url, &second_request).await {
        Ok(response) => response,
        Err(fault) => {
            trace.fail(fault, started);
            return trace;
        }
    };
    trace.reflection_response = Some(sanitize(&second_response));
    trace.transition(
        FlowState::FinalReceived,
        "provider returned second-pass message",
    );
    let final_output = match extract_final_output(&second_response, case, &observation) {
        Ok(output) => output,
        Err(detail) => {
            trace.fail(LoopFault::new("final_schema_fault", detail), started);
            return trace;
        }
    };
    trace.final_output = Some(final_output);
    trace.pass(FlowState::Completed, started);
    trace
}

async fn run_control_case(client: &Client, base_url: &str, model: &str) -> CaseTrace {
    let started = Instant::now();
    let request = control_request(model);
    let mut trace = CaseTrace::new(&CONTROL_CASE, request.clone());
    trace.transition(
        FlowState::FirstInferenceRequested,
        "submitted one provider request without a tools field",
    );
    let response = match post_chat(client, base_url, &request).await {
        Ok(response) => response,
        Err(fault) => {
            trace.fail(fault, started);
            return trace;
        }
    };
    trace.first_response = Some(sanitize(&response));
    trace.transition(
        FlowState::FinalReceived,
        "provider returned no-tool baseline message",
    );
    let output = match extract_control_output(&response) {
        Ok(output) => output,
        Err(detail) => {
            trace.fail(LoopFault::new("final_schema_fault", detail), started);
            return trace;
        }
    };
    trace.final_output = Some(output);
    trace.pass(FlowState::ControlCompleted, started);
    trace
}

async fn invoke_mcp(
    program: &Path,
    config: &Path,
    arguments: &cantor_reflection_loop::RouteArguments,
) -> Result<Value, LoopFault> {
    let transport =
        TokioChildProcess::new(tokio::process::Command::new(program).configure(|command| {
            command.arg("--config").arg(config);
        }))
        .map_err(|error| LoopFault::new("mcp_launch_fault", error.to_string()))?;
    let client = ()
        .serve(transport)
        .await
        .map_err(|error| LoopFault::new("mcp_initialization_fault", error.to_string()))?;
    let result = async {
        let peer = client
            .peer_info()
            .ok_or_else(|| LoopFault::new("mcp_identity_fault", "server omitted peer info"))?;
        if peer.instructions.as_deref() != Some(SERVER_INSTRUCTIONS) {
            return Err(LoopFault::new(
                "mcp_identity_fault",
                "server instructions differ from the compiled contract",
            ));
        }
        let tools = client
            .list_all_tools()
            .await
            .map_err(|error| LoopFault::new("mcp_protocol_fault", error.to_string()))?;
        if tools.len() != 1 || tools[0].name != TOOL_NAME {
            return Err(LoopFault::new(
                "mcp_identity_fault",
                "server did not expose exactly one route_attention tool",
            ));
        }
        let object: JsonObject = serde_json::to_value(arguments)
            .expect("RouteArguments always serializes")
            .as_object()
            .expect("RouteArguments serializes as an object")
            .clone();
        let response = client
            .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(object))
            .await
            .map_err(|error| LoopFault::new("mcp_protocol_fault", error.to_string()))?;
        response
            .structured_content
            .ok_or_else(|| LoopFault::new("mcp_result_fault", "result omitted structuredContent"))
    }
    .await;
    client
        .cancel()
        .await
        .map_err(|error| LoopFault::new("mcp_shutdown_fault", error.to_string()))?;
    result
}

async fn health_check(client: &Client, base_url: &str) -> Result<(), AnyError> {
    let root = base_url.strip_suffix("/v1").unwrap_or(base_url);
    let response = client.get(format!("{root}/health")).send().await?;
    if !response.status().is_success() {
        return Err(format!("llama.cpp health returned HTTP {}", response.status()).into());
    }
    Ok(())
}

async fn discover_model(client: &Client, base_url: &str) -> Result<String, AnyError> {
    let response = client.get(format!("{base_url}/models")).send().await?;
    if !response.status().is_success() {
        return Err(format!("model discovery returned HTTP {}", response.status()).into());
    }
    let value: Value = response.json().await?;
    let models = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or("model discovery omitted data array")?;
    if models.len() != 1 {
        return Err(format!(
            "expected exactly one advertised model, observed {}",
            models.len()
        )
        .into());
    }
    models[0]
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "advertised model omitted id".into())
}

async fn post_chat(client: &Client, base_url: &str, request: &Value) -> Result<Value, LoopFault> {
    let response = client
        .post(format!("{base_url}/chat/completions"))
        .json(request)
        .send()
        .await
        .map_err(|error| LoopFault::new("provider_fault", error.to_string()))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| LoopFault::new("provider_fault", error.to_string()))?;
    if !status.is_success() {
        return Err(LoopFault::new(
            "provider_fault",
            format!("HTTP {status}: {}", bounded(&text, 2_000)),
        ));
    }
    serde_json::from_str(&text).map_err(|error| {
        LoopFault::new(
            "provider_fault",
            format!(
                "response is not JSON: {error}; body={}",
                bounded(&text, 2_000)
            ),
        )
    })
}

fn canonical_file(path: &Path, role: &str) -> Result<PathBuf, AnyError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {role} {}: {error}", path.display()))?;
    if !canonical.is_file() {
        return Err(format!("{role} is not a regular file: {}", canonical.display()).into());
    }
    Ok(canonical)
}

fn sha256_file(path: &Path) -> Result<String, AnyError> {
    let mut hash = Sha256::new();
    hash.update(fs::read(path)?);
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn new_trace_id() -> String {
    format!("trace-{}", unix_time_ms())
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn bounded(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_arguments(output: &Path) -> Vec<String> {
        vec![
            "--mcp-program".to_owned(),
            "adapter.exe".to_owned(),
            "--mcp-config".to_owned(),
            "config.json".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
        ]
    }

    fn unique_test_path(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "cantor-reflection-loop-{label}-{}-{}",
            std::process::id(),
            unix_time_ms()
        ))
    }

    #[test]
    fn live_provider_is_restricted_to_loopback_http_v1() {
        let output = unique_test_path("loopback-report.json");
        let valid = Config::parse(base_arguments(&output)).unwrap();
        assert_eq!(valid.base_url, "http://127.0.0.1:8081/v1");

        let mut remote = base_arguments(&output);
        remote.extend(["--base-url".to_owned(), "https://example.com/v1".to_owned()]);
        assert!(Config::parse(remote).is_err());

        let mut wrong_path = base_arguments(&output);
        wrong_path.extend([
            "--base-url".to_owned(),
            "http://localhost:8081/api".to_owned(),
        ]);
        assert!(Config::parse(wrong_path).is_err());

        let mut partial = base_arguments(&output);
        partial.extend(["--case".to_owned(), "positive".to_owned()]);
        assert!(Config::parse(partial).is_err());

        let mut explicit_model = base_arguments(&output);
        explicit_model.extend(["--model".to_owned(), "substitute".to_owned()]);
        assert!(Config::parse(explicit_model).is_err());
    }

    #[test]
    fn report_publication_is_create_new() {
        let root = unique_test_path("create-new");
        fs::create_dir(&root).unwrap();
        let report = root.join("report.json");
        write_json_new(&report, &json!({"status": "first"})).unwrap();
        let first = fs::read(&report).unwrap();
        assert!(write_json_new(&report, &json!({"status": "second"})).is_err());
        assert_eq!(fs::read(&report).unwrap(), first);
        assert!(Config::parse(base_arguments(&report)).is_err());
        fs::remove_file(report).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
