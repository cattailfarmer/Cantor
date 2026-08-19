use cantor_field_cycle::{
    CURRENT_REQUEST_PROFILE, CYCLE_PROFILE, CycleEvent, CycleReport, CycleState,
    DelineationProposal, LatchStatus, MAX_BOUNDARY_REASON_BYTES, MAX_ELEMENT_CONTENT_BYTES,
    MAX_FIELD_FILE_BYTES, MAX_IDENTIFIER_BYTES, MAX_PROVIDER_BASE_URL_BYTES,
    MAX_PROVIDER_MODEL_BYTES, MAX_PURPOSE_BYTES, MAX_REPORT_FILE_BYTES, MAX_SOURCE_REF_BYTES,
    MAX_SUBJECT_BYTES, ProviderIdentity, SemanticField, admit_probe, aggregate_candidate,
    canonical_digest, delineation_request, field_request, fixture_report, latch,
    normalize_loopback_base_url, parse_delineation_response, parse_probe_response,
    provider_exchange, sha256_hex, validate_delineation, validate_field, verify_report,
};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type AnyError = Box<dyn Error + Send + Sync>;
const PROVIDER_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const PROVIDER_REQUEST_TIMEOUT_SECONDS: u64 = 90;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match dispatch(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cantor-field-cycle: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(arguments: Vec<String>) -> Result<(), AnyError> {
    let Some(command) = arguments.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };
    match command {
        "contract" => {
            print_json(&serde_json::json!({
                "profile": CYCLE_PROFILE,
                "request_profile": CURRENT_REQUEST_PROFILE,
                "field_profile": cantor_field_cycle::FIELD_PROFILE,
                "probe_count": cantor_field_cycle::PROBE_COUNT,
                "minimum_support": cantor_field_cycle::MINIMUM_SUPPORT,
                "provider_connect_timeout_seconds": PROVIDER_CONNECT_TIMEOUT_SECONDS,
                "provider_request_timeout_seconds": PROVIDER_REQUEST_TIMEOUT_SECONDS,
                "max_provider_response_bytes": MAX_PROVIDER_RESPONSE_BYTES,
                "provider_proxy_policy": "disabled",
                "provider_redirect_limit": 0,
                "resource_budgets": {
                    "identifier_bytes": MAX_IDENTIFIER_BYTES,
                    "subject_bytes": MAX_SUBJECT_BYTES,
                    "purpose_bytes": MAX_PURPOSE_BYTES,
                    "element_content_bytes": MAX_ELEMENT_CONTENT_BYTES,
                    "source_ref_bytes": MAX_SOURCE_REF_BYTES,
                    "boundary_reason_bytes": MAX_BOUNDARY_REASON_BYTES,
                    "provider_model_bytes": MAX_PROVIDER_MODEL_BYTES,
                    "provider_base_url_bytes": MAX_PROVIDER_BASE_URL_BYTES,
                    "semantic_field_file_bytes": MAX_FIELD_FILE_BYTES,
                    "cycle_report_file_bytes": MAX_REPORT_FILE_BYTES
                },
                "states": ["created", "field_validated", "probes_requested", "probes_collected", "candidate_aggregated", "delineation_requested", "delineation_collected", "latch_evaluated", "completed", "rejected", "faulted", "control_completed"],
                "verification_assurance": ["deterministic_construction", "stored_provider_replay", "response_backed_fault_replay", "structural_runtime_fault_only"],
                "authority": "attention-local proposal and admission only"
            }))?;
        }
        "field-digest" => {
            let field = read_field(required(&arguments, 1, "FIELD.json")?)?;
            validate_field(&field)?;
            println!("{}", canonical_digest(&field)?);
        }
        "fixture" => fixture_command(&arguments[1..])?,
        "run" => run_command(&arguments[1..]).await?,
        "control" => control_command(&arguments[1..]).await?,
        "verify" => {
            let path = Path::new(required(&arguments, 1, "REPORT.json")?);
            let report: CycleReport = read_json(path, MAX_REPORT_FILE_BYTES, "cycle report")?;
            print_json(&verify_report(&report)?)?;
        }
        "help" | "--help" | "-h" => print_help(),
        unknown => return Err(format!("unknown command {unknown:?}").into()),
    }
    Ok(())
}

fn fixture_command(arguments: &[String]) -> Result<(), AnyError> {
    if arguments.len() != 2 {
        return Err("fixture requires FIELD.json REPORT.json".into());
    }
    let field = read_field(&arguments[0])?;
    let report = fixture_report(field)?;
    let verification = verify_report(&report)?;
    let output = Path::new(&arguments[1]);
    write_json_new(output, &report)?;
    print_json(&serde_json::json!({
        "report": output,
        "verification": verification
    }))
}

async fn run_command(arguments: &[String]) -> Result<(), AnyError> {
    let mut field_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut base_url = "http://127.0.0.1:8081".to_owned();
    let mut model: Option<String> = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--field" => field_path = Some(PathBuf::from(next(arguments, &mut index, "--field")?)),
            "--out" => output_path = Some(PathBuf::from(next(arguments, &mut index, "--out")?)),
            "--base-url" => base_url = next(arguments, &mut index, "--base-url")?.to_owned(),
            "--model" => model = Some(next(arguments, &mut index, "--model")?.to_owned()),
            unknown => return Err(format!("unknown run argument {unknown:?}").into()),
        }
        index += 1;
    }
    let field_path = field_path.ok_or("run requires --field FIELD.json")?;
    let output_path = output_path.ok_or("run requires --out REPORT.json")?;
    let base_url = normalize_loopback_base_url(&base_url)?;
    let field = read_field(&field_path)?;
    validate_field(&field)?;
    let client = provider_client()?;
    let model = match model {
        Some(model) => model,
        None => discover_model(&client, &base_url).await?,
    };
    let report = execute_cycle(&client, &base_url, &model, field).await;
    let verification = verify_report(&report)
        .map_err(|error| format!("cycle produced an unverifiable report: {error}"))?;
    write_json_new(&output_path, &report)?;
    print_json(&serde_json::json!({
        "report": output_path,
        "terminal_state": report.terminal_state,
        "latch_status": report.latch_decision.as_ref().map(|decision| decision.status),
        "fault": report.fault,
        "verification": verification
    }))?;
    Ok(())
}

async fn control_command(arguments: &[String]) -> Result<(), AnyError> {
    let mut field_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut base_url = "http://127.0.0.1:8081".to_owned();
    let mut model: Option<String> = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--field" => field_path = Some(PathBuf::from(next(arguments, &mut index, "--field")?)),
            "--out" => output_path = Some(PathBuf::from(next(arguments, &mut index, "--out")?)),
            "--base-url" => base_url = next(arguments, &mut index, "--base-url")?.to_owned(),
            "--model" => model = Some(next(arguments, &mut index, "--model")?.to_owned()),
            unknown => return Err(format!("unknown control argument {unknown:?}").into()),
        }
        index += 1;
    }
    let field_path = field_path.ok_or("control requires --field FIELD.json")?;
    let output_path = output_path.ok_or("control requires --out REPORT.json")?;
    let base_url = normalize_loopback_base_url(&base_url)?;
    let field = read_field(&field_path)?;
    validate_field(&field)?;
    let client = provider_client()?;
    let model = match model {
        Some(model) => model,
        None => discover_model(&client, &base_url).await?,
    };
    let report = execute_control(&client, &base_url, &model, field).await;
    let verification = verify_report(&report)
        .map_err(|error| format!("control produced an unverifiable report: {error}"))?;
    write_json_new(&output_path, &report)?;
    print_json(&serde_json::json!({
        "report": output_path,
        "terminal_state": report.terminal_state,
        "latch_eligible": false,
        "fault": report.fault,
        "verification": verification
    }))?;
    Ok(())
}

async fn execute_cycle(
    client: &Client,
    base_url: &str,
    model: &str,
    field: SemanticField,
) -> CycleReport {
    let field_digest = canonical_digest(&field).expect("validated field serializes");
    let mut report = CycleReport {
        profile: CYCLE_PROFILE.to_owned(),
        request_profile: CURRENT_REQUEST_PROFILE.to_owned(),
        run_id: format!("{}-{}", unix_time_ms(), std::process::id()),
        provider: ProviderIdentity {
            base_url: base_url.to_owned(),
            model: model.to_owned(),
        },
        field,
        field_digest,
        events: Vec::new(),
        exchanges: Vec::new(),
        probes: Vec::new(),
        candidate: None,
        delineation_proposal: None,
        delineation_result: None,
        latch_decision: None,
        terminal_state: CycleState::Created,
        fault: None,
    };
    event(&mut report, CycleState::Created, "field-input");
    event(&mut report, CycleState::FieldValidated, "field-digest");
    event(&mut report, CycleState::ProbesRequested, "probe-orders");

    for probe_index in 0..cantor_field_cycle::PROBE_COUNT {
        let request = match field_request(model, &report.field, probe_index) {
            Ok(request) => request,
            Err(error) => return fault(report, error),
        };
        let response = match post_chat(client, base_url, &request).await {
            Ok(response) => response,
            Err(error) => return fault(report, error.to_string()),
        };
        let proposal = match parse_probe_response(CURRENT_REQUEST_PROFILE, &report.field, &response)
        {
            Ok(proposal) => proposal,
            Err(error) => {
                return fault_with_exchange(report, request, response, probe_index, error);
            }
        };
        let probe = match admit_probe(&report.field, probe_index, proposal) {
            Ok(probe) => probe,
            Err(error) => {
                return fault_with_exchange(report, request, response, probe_index, error);
            }
        };
        match provider_exchange(
            format!("field_probe_{}", probe_index + 1),
            request,
            response,
        ) {
            Ok(exchange) => report.exchanges.push(exchange),
            Err(error) => return fault(report, error),
        }
        report.probes.push(probe);
    }
    event(&mut report, CycleState::ProbesCollected, "field-probes");
    let candidate = match aggregate_candidate(&report.field, &report.probes) {
        Ok(candidate) => candidate,
        Err(error) => {
            report.fault = Some(error);
            event(&mut report, CycleState::Rejected, "aggregation-rejection");
            return report;
        }
    };
    report.candidate = Some(candidate.clone());
    event(
        &mut report,
        CycleState::CandidateAggregated,
        "gestalt-candidate",
    );
    event(
        &mut report,
        CycleState::DelineationRequested,
        "delineation-request",
    );
    let request = match delineation_request(model, &report.field, &candidate) {
        Ok(request) => request,
        Err(error) => return fault(report, error),
    };
    let response = match post_chat(client, base_url, &request).await {
        Ok(response) => response,
        Err(error) => return fault(report, error.to_string()),
    };
    let proposal: DelineationProposal =
        match parse_delineation_response(CURRENT_REQUEST_PROFILE, &candidate, &response) {
            Ok(proposal) => proposal,
            Err(error) => {
                return fault_with_named_exchange(report, request, response, "delineation", error);
            }
        };
    match provider_exchange("delineation", request, response) {
        Ok(exchange) => report.exchanges.push(exchange),
        Err(error) => return fault(report, error),
    }
    let result = validate_delineation(&report.field, &candidate, &proposal);
    let decision = latch(&report.field, &candidate, &result);
    report.delineation_proposal = Some(proposal);
    report.delineation_result = Some(result);
    event(
        &mut report,
        CycleState::DelineationCollected,
        "delineation-result",
    );
    report.latch_decision = Some(decision.clone());
    event(&mut report, CycleState::LatchEvaluated, "latch-decision");
    let terminal = if decision.status == LatchStatus::AdmittedForAttention {
        CycleState::Completed
    } else {
        CycleState::Rejected
    };
    event(&mut report, terminal, "terminal-decision");
    report
}

async fn execute_control(
    client: &Client,
    base_url: &str,
    model: &str,
    field: SemanticField,
) -> CycleReport {
    let field_digest = canonical_digest(&field).expect("validated field serializes");
    let mut report = CycleReport {
        profile: CYCLE_PROFILE.to_owned(),
        request_profile: CURRENT_REQUEST_PROFILE.to_owned(),
        run_id: format!("control-{}-{}", unix_time_ms(), std::process::id()),
        provider: ProviderIdentity {
            base_url: base_url.to_owned(),
            model: model.to_owned(),
        },
        field,
        field_digest,
        events: Vec::new(),
        exchanges: Vec::new(),
        probes: Vec::new(),
        candidate: None,
        delineation_proposal: None,
        delineation_result: None,
        latch_decision: None,
        terminal_state: CycleState::Created,
        fault: None,
    };
    event(&mut report, CycleState::Created, "control-field-input");
    event(
        &mut report,
        CycleState::FieldValidated,
        "control-field-digest",
    );
    let request = match field_request(model, &report.field, 0) {
        Ok(request) => request,
        Err(error) => return fault(report, error),
    };
    let response = match post_chat(client, base_url, &request).await {
        Ok(response) => response,
        Err(error) => return fault(report, error.to_string()),
    };
    let proposal = match parse_probe_response(CURRENT_REQUEST_PROFILE, &report.field, &response) {
        Ok(proposal) => proposal,
        Err(error) => {
            return fault_with_named_exchange(report, request, response, "control_probe_1", error);
        }
    };
    let probe = match admit_probe(&report.field, 0, proposal) {
        Ok(probe) => probe,
        Err(error) => {
            return fault_with_named_exchange(report, request, response, "control_probe_1", error);
        }
    };
    match provider_exchange("control_probe_1", request, response) {
        Ok(exchange) => report.exchanges.push(exchange),
        Err(error) => return fault(report, error),
    }
    report.probes.push(probe);
    event(
        &mut report,
        CycleState::ControlCompleted,
        "control-probe-only-no-latch",
    );
    report
}

fn event(report: &mut CycleReport, state: CycleState, evidence_ref: &str) {
    report.events.push(CycleEvent {
        ordinal: report.events.len() + 1,
        state,
        evidence_ref: evidence_ref.to_owned(),
    });
    report.terminal_state = state;
}

fn fault(mut report: CycleReport, error: String) -> CycleReport {
    report.fault = Some(error);
    event(&mut report, CycleState::Faulted, "typed-fault");
    report
}

fn fault_with_exchange(
    report: CycleReport,
    request: Value,
    response: Value,
    probe_index: usize,
    error: String,
) -> CycleReport {
    fault_with_named_exchange(
        report,
        request,
        response,
        &format!("field_probe_{}", probe_index + 1),
        error,
    )
}

fn fault_with_named_exchange(
    mut report: CycleReport,
    request: Value,
    response: Value,
    stage: &str,
    error: String,
) -> CycleReport {
    if let Ok(exchange) = provider_exchange(stage, request, response) {
        report.exchanges.push(exchange);
    }
    fault(report, error)
}

async fn post_chat(client: &Client, base_url: &str, request: &Value) -> Result<Value, AnyError> {
    let response = client
        .post(format!("{base_url}/v1/chat/completions"))
        .json(request)
        .send()
        .await?;
    let status = response.status();
    let bytes = read_response_bytes(response).await?;
    if !status.is_success() {
        return Err(format!(
            "provider returned HTTP {status}; body_bytes={}; body_sha256={}",
            bytes.len(),
            sha256_hex(&bytes)
        )
        .into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn discover_model(client: &Client, base_url: &str) -> Result<String, AnyError> {
    let response = client
        .get(format!("{base_url}/v1/models"))
        .send()
        .await?
        .error_for_status()?;
    let bytes = read_response_bytes(response).await?;
    let response: Value = serde_json::from_slice(&bytes)?;
    response
        .pointer("/data/0/id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "provider /v1/models omitted data[0].id".into())
}

fn provider_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(PROVIDER_CONNECT_TIMEOUT_SECONDS))
        .timeout(Duration::from_secs(PROVIDER_REQUEST_TIMEOUT_SECONDS))
        .build()
}

async fn read_response_bytes(mut response: reqwest::Response) -> Result<Vec<u8>, AnyError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(
            format!("provider response exceeds {MAX_PROVIDER_RESPONSE_BYTES} byte limit").into(),
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_response_chunk(&mut bytes, &chunk)?;
    }
    Ok(bytes)
}

fn append_response_chunk(buffer: &mut Vec<u8>, chunk: &[u8]) -> Result<(), AnyError> {
    let remaining = MAX_PROVIDER_RESPONSE_BYTES.saturating_sub(buffer.len());
    if chunk.len() > remaining {
        return Err(
            format!("provider response exceeds {MAX_PROVIDER_RESPONSE_BYTES} byte limit").into(),
        );
    }
    buffer.extend_from_slice(chunk);
    Ok(())
}

fn read_field(path: impl AsRef<Path>) -> Result<SemanticField, AnyError> {
    read_json(path.as_ref(), MAX_FIELD_FILE_BYTES, "semantic field")
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<T, AnyError> {
    let mut file = File::open(path)?;
    ensure_file_size(label, file.metadata()?.len(), maximum_bytes)?;
    let bytes = read_body_limited(&mut file, maximum_bytes, label)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_body_limited(
    reader: &mut impl Read,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, AnyError> {
    let read_ceiling = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| format!("{label} byte file limit cannot be represented"))?;
    let mut bytes = Vec::new();
    reader.take(read_ceiling).read_to_end(&mut bytes)?;
    ensure_file_size(label, bytes.len() as u64, maximum_bytes)?;
    Ok(bytes)
}

fn ensure_file_size(label: &str, observed: u64, maximum: u64) -> Result<(), AnyError> {
    if observed > maximum {
        return Err(format!("{label} exceeds {maximum} byte file limit").into());
    }
    Ok(())
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), AnyError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure_file_size(
        "serialized cycle report",
        bytes.len() as u64 + 1,
        MAX_REPORT_FILE_BYTES,
    )?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn print_json(value: &impl Serialize) -> Result<(), AnyError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn required<'a>(arguments: &'a [String], index: usize, label: &str) -> Result<&'a str, AnyError> {
    arguments
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {label}").into())
}

fn next<'a>(arguments: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, AnyError> {
    *index += 1;
    arguments
        .get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must follow Unix epoch")
        .as_millis()
}

fn print_help() {
    println!(
        "cantor-field-cycle\n\
         commands:\n\
           contract\n\
           field-digest FIELD.json\n\
           fixture FIELD.json REPORT.json\n\
           run --field FIELD.json --out REPORT.json [--base-url http://127.0.0.1:8081] [--model MODEL]\n\
           control --field FIELD.json --out REPORT.json [--base-url http://127.0.0.1:8081] [--model MODEL]\n\
           verify REPORT.json"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_validation_rejects_remote_and_userinfo() {
        assert!(normalize_loopback_base_url("http://127.0.0.1:8081").is_ok());
        assert!(normalize_loopback_base_url("http://localhost:8081/").is_ok());
        assert!(normalize_loopback_base_url("http://192.168.1.19:8081").is_err());
        assert!(normalize_loopback_base_url("http://user@127.0.0.1:8081").is_err());
        assert!(normalize_loopback_base_url("http://localhost:8081/path").is_err());
        assert!(normalize_loopback_base_url("http://localhost:not-a-port").is_err());
        assert!(normalize_loopback_base_url("http://localhost:0").is_err());
    }

    #[test]
    fn response_buffer_is_bounded() {
        let mut buffer = vec![0; MAX_PROVIDER_RESPONSE_BYTES - 1];
        assert!(append_response_chunk(&mut buffer, &[1]).is_ok());
        assert_eq!(buffer.len(), MAX_PROVIDER_RESPONSE_BYTES);
        assert!(append_response_chunk(&mut buffer, &[2]).is_err());
    }

    #[test]
    fn provider_failure_evidence_can_be_content_private() {
        let secret = b"private provider diagnostic";
        let evidence = format!(
            "body_bytes={}; body_sha256={}",
            secret.len(),
            sha256_hex(secret)
        );
        assert!(!evidence.contains("private provider diagnostic"));
        assert!(evidence.contains("body_bytes=27"));
    }

    #[test]
    fn file_size_budget_rejects_before_deserialization() {
        assert!(ensure_file_size("fixture", MAX_FIELD_FILE_BYTES, MAX_FIELD_FILE_BYTES).is_ok());
        assert!(
            ensure_file_size("fixture", MAX_FIELD_FILE_BYTES + 1, MAX_FIELD_FILE_BYTES)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        assert_eq!(
            read_body_limited(&mut std::io::Cursor::new(b"1234"), 4, "fixture").unwrap(),
            b"1234"
        );
        assert!(
            read_body_limited(&mut std::io::Cursor::new(b"12345"), 4, "fixture")
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
    }
}
