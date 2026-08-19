#![forbid(unsafe_code)]

use std::{
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use cantor_compact_reflection_loop::{
    CheckpointCustodyQuery, REPORT_NONCLAIMS, REPORT_PROFILE, RunReport,
    advance_bound_session_terminal, dispatch_checkpoint_custody_query,
    experimental_fixture_context_json, extract_advance_call, extract_final_output, first_request,
    generate_custody_query_surface_measurement, generate_dispatch_checkpoint_handle_measurement,
    generate_fixture_deterministic_drive_measurement, generate_fixture_transport_measurement,
    generate_iterative_transcript_measurement, generate_provider_free_attention_lineage_index,
    generate_provider_free_shell_release_manifest, generate_scripted_checkpoint_custody_registry,
    inspect_report, normalize_loopback_base_url, open_bound_session,
    pretty_checkpoint_custody_response_bytes, pretty_custody_query_surface_measurement_bytes,
    pretty_deterministic_drive_measurement_bytes,
    pretty_dispatch_checkpoint_handle_measurement_bytes,
    pretty_iterative_transcript_measurement_bytes,
    pretty_provider_free_attention_lineage_index_bytes,
    pretty_provider_free_shell_release_manifest_bytes, pretty_transport_measurement_bytes,
    project_terminal_observation, reflection_request, sanitize, select_advertised_model,
    verify_report,
};
use cantor_core::SemanticId;
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

type AnyError = Box<dyn Error + Send + Sync>;
const MAX_CONTEXT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROMPT_BYTES: usize = 32 * 1024;
const MAX_CUSTODY_QUERY_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct Config {
    base_url: String,
    context: PathBuf,
    output: PathBuf,
    session_id: SemanticId,
    prompt: String,
    maximum_steps: u64,
    timeout: Duration,
    model: Option<String>,
}

impl Config {
    fn parse(arguments: Vec<String>) -> Result<Self, AnyError> {
        let mut base_url = "http://127.0.0.1:8081/v1".to_owned();
        let mut context = None;
        let mut output = PathBuf::from("cantor_compact_reflection_report.json");
        let mut session_id = "session:compact-reflection-local".to_owned();
        let mut prompt = None;
        let mut maximum_steps = 64_u64;
        let mut timeout = Duration::from_secs(180);
        let mut model = None;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--base-url" => base_url = required(&mut arguments, "--base-url")?,
                "--context" => {
                    context = Some(PathBuf::from(required(&mut arguments, "--context")?));
                }
                "--output" => output = PathBuf::from(required(&mut arguments, "--output")?),
                "--session-id" => session_id = required(&mut arguments, "--session-id")?,
                "--prompt" => prompt = Some(required(&mut arguments, "--prompt")?),
                "--model" => model = Some(required(&mut arguments, "--model")?),
                "--maximum-steps" => {
                    maximum_steps = required(&mut arguments, "--maximum-steps")?.parse()?;
                }
                "--timeout-seconds" => {
                    timeout = Duration::from_secs(
                        required(&mut arguments, "--timeout-seconds")?.parse()?,
                    );
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                value => return Err(format!("unknown argument: {value}").into()),
            }
        }
        let context = context.ok_or("--context is required")?;
        let prompt = prompt.ok_or("--prompt is required")?;
        if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES {
            return Err(format!("prompt must contain 1..={MAX_PROMPT_BYTES} bytes").into());
        }
        if !(1..=4096).contains(&maximum_steps) {
            return Err("maximum-steps must be within 1..=4096".into());
        }
        if timeout.is_zero() || timeout > Duration::from_secs(600) {
            return Err("timeout-seconds must be within 1..=600".into());
        }
        if model.as_ref().is_some_and(String::is_empty) {
            return Err("model identity cannot be empty".into());
        }
        if output.exists() {
            return Err(format!("output already exists: {}", output.display()).into());
        }
        Ok(Self {
            base_url: normalize_loopback_base_url(&base_url)?,
            context,
            output,
            session_id: SemanticId::new(session_id)?,
            prompt,
            maximum_steps,
            timeout,
            model,
        })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if matches!(
        arguments.first().map(String::as_str),
        Some("verify" | "inspect")
    ) {
        return report_command(&arguments);
    }
    if arguments.first().map(String::as_str) == Some("measure-fixture") {
        if arguments.len() != 1 {
            eprintln!("configuration_fault: usage: cantor-compact-reflection-loop measure-fixture");
            return ExitCode::from(2);
        }
        return measurement_command();
    }
    if arguments.first().map(String::as_str) == Some("measure-iterative-fixture") {
        if arguments.len() != 1 {
            eprintln!(
                "configuration_fault: usage: cantor-compact-reflection-loop measure-iterative-fixture"
            );
            return ExitCode::from(2);
        }
        return iterative_measurement_command();
    }
    if arguments.first().map(String::as_str) == Some("measure-iterative-transcript-fixture") {
        if arguments.len() != 1 {
            eprintln!(
                "configuration_fault: usage: cantor-compact-reflection-loop measure-iterative-transcript-fixture"
            );
            return ExitCode::from(2);
        }
        return iterative_transcript_measurement_command();
    }
    if arguments.first().map(String::as_str) == Some("measure-dispatch-checkpoint-handles") {
        if arguments.len() != 1 {
            eprintln!(
                "configuration_fault: usage: cantor-compact-reflection-loop measure-dispatch-checkpoint-handles"
            );
            return ExitCode::from(2);
        }
        return dispatch_checkpoint_handle_measurement_command();
    }
    if arguments.first().map(String::as_str) == Some("index-provider-free-lineage") {
        if arguments.len() != 1 {
            eprintln!(
                "configuration_fault: usage: cantor-compact-reflection-loop index-provider-free-lineage"
            );
            return ExitCode::from(2);
        }
        return provider_free_lineage_index_command();
    }
    if arguments.first().map(String::as_str) == Some("query-scripted-checkpoint-custody") {
        if arguments.len() != 1 {
            eprintln!(
                "configuration_fault: usage: cantor-compact-reflection-loop query-scripted-checkpoint-custody"
            );
            return ExitCode::from(2);
        }
        return scripted_checkpoint_custody_query_command();
    }
    if arguments.first().map(String::as_str) == Some("measure-checkpoint-custody-query-surface") {
        if arguments.len() != 1 {
            eprintln!(
                "configuration_fault: usage: cantor-compact-reflection-loop measure-checkpoint-custody-query-surface"
            );
            return ExitCode::from(2);
        }
        return custody_query_surface_measurement_command();
    }
    if arguments.first().map(String::as_str) == Some("describe-provider-free-shell-release") {
        if arguments.len() != 1 {
            eprintln!(
                "configuration_fault: usage: cantor-compact-reflection-loop describe-provider-free-shell-release"
            );
            return ExitCode::from(2);
        }
        return provider_free_shell_release_command();
    }
    if arguments.first().map(String::as_str) == Some("fixture-context") {
        return fixture_context_command(&arguments[1..]);
    }
    let config = match Config::parse(arguments) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration_fault: {error}");
            return ExitCode::from(2);
        }
    };
    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("run_fault: {error}");
            ExitCode::from(1)
        }
    }
}

async fn run(config: Config) -> Result<(), AnyError> {
    let context_path = canonical_bounded_context(&config.context)?;
    let context_json = fs::read_to_string(&context_path)?;
    let context_sha256 = hex_digest(context_json.as_bytes());
    let session = open_bound_session(
        context_json,
        SemanticId::new("registry:compact-reflection-local")?,
        config.session_id.clone(),
    )?;

    let client = Client::builder().timeout(config.timeout).build()?;
    health_check(&client, &config.base_url).await?;
    let model = discover_model(&client, &config.base_url, config.model.as_deref()).await?;
    let initial_request = first_request(&model, &config.prompt, config.maximum_steps);
    let initial_response = post_chat(&client, &config.base_url, &initial_request).await?;
    let call = extract_advance_call(&initial_response, config.maximum_steps)?;
    let (_terminal_session, observation) =
        advance_bound_session_terminal(&session, call.arguments.maximum_steps)?;
    let projection = project_terminal_observation(&observation)?;
    let later_request = reflection_request(&model, &config.prompt, &call, &projection);
    let later_response = post_chat(&client, &config.base_url, &later_request).await?;
    let final_output = extract_final_output(&later_response, &projection)?;

    let report = RunReport {
        profile: REPORT_PROFILE.to_owned(),
        status: "passed".to_owned(),
        base_url: config.base_url,
        model,
        context_path: context_path.display().to_string(),
        context_sha256,
        session_id: config.session_id,
        maximum_steps: config.maximum_steps,
        first_request: initial_request,
        first_response: sanitize(&initial_response),
        terminal_observation: observation,
        terminal_projection: projection,
        reflection_request: later_request,
        reflection_response: sanitize(&later_response),
        final_output,
        private_reasoning_recorded: false,
        nonclaims: REPORT_NONCLAIMS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    };
    write_json_new(&config.output, &report)?;
    println!("PASS: report written to {}", config.output.display());
    Ok(())
}

async fn health_check(client: &Client, base_url: &str) -> Result<(), AnyError> {
    let root = base_url.strip_suffix("/v1").unwrap_or(base_url);
    let response = client.get(root).send().await?;
    if !response.status().is_success() {
        return Err(format!("provider health returned HTTP {}", response.status()).into());
    }
    Ok(())
}

async fn discover_model(
    client: &Client,
    base_url: &str,
    requested: Option<&str>,
) -> Result<String, AnyError> {
    let response = client.get(format!("{base_url}/models")).send().await?;
    if !response.status().is_success() {
        return Err(format!("model discovery returned HTTP {}", response.status()).into());
    }
    let value: Value = response.json().await?;
    select_advertised_model(&value, requested).map_err(Into::into)
}

async fn post_chat(client: &Client, base_url: &str, request: &Value) -> Result<Value, AnyError> {
    let response = client
        .post(format!("{base_url}/chat/completions"))
        .json(request)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("provider response exceeds 8 MiB".into());
    }
    if !status.is_success() {
        return Err(format!(
            "provider returned HTTP {status}: {}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(2000)])
        )
        .into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn canonical_bounded_context(path: &Path) -> Result<PathBuf, AnyError> {
    let canonical = fs::canonicalize(path)?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONTEXT_BYTES {
        return Err(format!(
            "context must be a nonempty regular file at most {MAX_CONTEXT_BYTES} bytes"
        )
        .into());
    }
    Ok(canonical)
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), AnyError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn required(arguments: &mut impl Iterator<Item = String>, name: &str) -> Result<String, AnyError> {
    arguments
        .next()
        .ok_or_else(|| format!("{name} requires a value").into())
}

fn fixture_context_command(arguments: &[String]) -> ExitCode {
    if arguments.len() != 2 || arguments[0] != "--output" {
        eprintln!(
            "configuration_fault: usage: cantor-compact-reflection-loop fixture-context --output PATH"
        );
        return ExitCode::from(2);
    }
    let path = Path::new(&arguments[1]);
    if path.exists() {
        eprintln!(
            "configuration_fault: output already exists: {}",
            path.display()
        );
        return ExitCode::from(2);
    }
    let context = match experimental_fixture_context_json() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("fixture_fault: {error}");
            return ExitCode::from(1);
        }
    };
    let result = (|| -> Result<(), AnyError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(context.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!(
                "FIXTURE: experimental nonauthoritative context written to {}",
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fixture_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn report_command(arguments: &[String]) -> ExitCode {
    if arguments.len() != 3 || arguments[1] != "--report" {
        eprintln!(
            "configuration_fault: usage: cantor-compact-reflection-loop verify|inspect --report PATH"
        );
        return ExitCode::from(2);
    }
    let path = Path::new(&arguments[2]);
    let report = match fs::read(path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<RunReport>(&bytes).map_err(|error| error.to_string())
        }) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("report_input_fault: {}: {error}", path.display());
            return ExitCode::from(2);
        }
    };
    let value = if arguments[0] == "verify" {
        verify_report(&report)
            .and_then(|value| serde_json::to_value(value).map_err(|error| error.to_string()))
    } else {
        inspect_report(&report)
            .and_then(|value| serde_json::to_value(value).map_err(|error| error.to_string()))
    };
    match value {
        Ok(value) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value)
                    .expect("verification projection always serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("report_verification_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn measurement_command() -> ExitCode {
    match generate_fixture_transport_measurement()
        .and_then(|measurement| pretty_transport_measurement_bytes(&measurement))
    {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("measurement_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn iterative_measurement_command() -> ExitCode {
    match generate_fixture_deterministic_drive_measurement()
        .and_then(|measurement| pretty_deterministic_drive_measurement_bytes(&measurement))
    {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("iterative_measurement_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn iterative_transcript_measurement_command() -> ExitCode {
    match generate_iterative_transcript_measurement()
        .and_then(|measurement| pretty_iterative_transcript_measurement_bytes(&measurement))
    {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("iterative_transcript_measurement_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn dispatch_checkpoint_handle_measurement_command() -> ExitCode {
    match generate_dispatch_checkpoint_handle_measurement()
        .and_then(|measurement| pretty_dispatch_checkpoint_handle_measurement_bytes(&measurement))
    {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("dispatch_checkpoint_handle_measurement_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn provider_free_lineage_index_command() -> ExitCode {
    match generate_provider_free_attention_lineage_index()
        .and_then(|index| pretty_provider_free_attention_lineage_index_bytes(&index))
    {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("provider_free_lineage_index_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn scripted_checkpoint_custody_query_command() -> ExitCode {
    let result = (|| -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_CUSTODY_QUERY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read checkpoint custody query: {error}"))?;
        if bytes.is_empty() {
            return Err("checkpoint custody query stdin is empty".to_owned());
        }
        if bytes.len() as u64 > MAX_CUSTODY_QUERY_BYTES {
            return Err(format!(
                "checkpoint custody query exceeds {MAX_CUSTODY_QUERY_BYTES} bytes"
            ));
        }
        let query: CheckpointCustodyQuery = serde_json::from_slice(&bytes)
            .map_err(|error| format!("checkpoint custody query JSON is invalid: {error}"))?;
        let registry = generate_scripted_checkpoint_custody_registry()?;
        let response = dispatch_checkpoint_custody_query(&registry, &query)?;
        pretty_checkpoint_custody_response_bytes(&registry, &query, &response)
    })();
    match result {
        Ok(bytes) => {
            if let Err(error) = std::io::stdout().write_all(&bytes) {
                eprintln!("checkpoint_custody_query_fault: {error}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("checkpoint_custody_query_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn custody_query_surface_measurement_command() -> ExitCode {
    match generate_custody_query_surface_measurement()
        .and_then(|measurement| pretty_custody_query_surface_measurement_bytes(&measurement))
    {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("custody_query_surface_measurement_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn provider_free_shell_release_command() -> ExitCode {
    match generate_provider_free_shell_release_manifest()
        .and_then(|manifest| pretty_provider_free_shell_release_manifest_bytes(&manifest))
    {
        Ok(bytes) => {
            print!("{}", String::from_utf8_lossy(&bytes));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("provider_free_shell_release_fault: {error}");
            ExitCode::from(1)
        }
    }
}

fn print_help() {
    println!(
        "cantor-compact-reflection-loop\n\
         \n\
         Runs one loopback model -> compact Cantor procedure -> model reflection P0.\n\
         \n\
         Offline report replay:\n\
           cantor-compact-reflection-loop verify --report PATH\n\
           cantor-compact-reflection-loop inspect --report PATH\n\
           cantor-compact-reflection-loop measure-fixture\n\
           cantor-compact-reflection-loop measure-iterative-fixture\n\
           cantor-compact-reflection-loop measure-iterative-transcript-fixture\n\
           cantor-compact-reflection-loop measure-dispatch-checkpoint-handles\n\
           cantor-compact-reflection-loop index-provider-free-lineage\n\
           echo QUERY_JSON | cantor-compact-reflection-loop query-scripted-checkpoint-custody\n\
           cantor-compact-reflection-loop measure-checkpoint-custody-query-surface\n\
           cantor-compact-reflection-loop describe-provider-free-shell-release\n\
         \n\
         Required:\n\
           --context PATH          exact CoordinationToolContext JSON\n\
           --prompt TEXT           bounded user stimulus\n\
           fixture-context --output PATH emits one experimental local proof context\n\
         Options:\n\
           --base-url URL          loopback OpenAI API root (default http://127.0.0.1:8081/v1)\n\
           --model ID              exact advertised model; required when more than one is advertised\n\
           --session-id ID         semantic session identity\n\
           --maximum-steps N       required one-call quota within 1..=4096 (default 64)\n\
           --output PATH           create-new JSON report path\n\
           --timeout-seconds N     provider timeout within 1..=600"
    );
}
