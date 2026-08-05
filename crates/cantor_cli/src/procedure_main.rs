//! Bounded process adapter for the effectless Cantor procedure experiment.
//!
//! This binary is intentionally not a model or provider controller. It
//! serializes the existing `cantor.exchange/0.1` fake-controller seam so an
//! external harness can inspect, run, and independently verify explicit
//! checkpoint artifacts.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use cantor_core::{
    AuthorshipLaneEvidence, ContentDigest, FakeControllerOutcome, ProviderNeutralToolSchema,
    SemanticId, ToolCallProposal, ToolResultDisposition, provider_neutral_exchange_schema,
    run_fake_controller_exchange, verify_fake_controller_outcome,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const RESPONSE_PROFILE: &str = "cantor-procedure-tool-cli/0.1";
const RELEASE_GRADE: &str = "effectless_internal_experiment_only";
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MESSAGE_CHARS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResponseStatus {
    Success,
    Refused,
    InvalidInput,
    VerificationFailure,
    InternalFault,
}

impl ResponseStatus {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::InvalidInput => 2,
            Self::Refused => 3,
            Self::VerificationFailure => 4,
            Self::InternalFault => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct CliFault {
    code: String,
    stage: String,
    message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationRecord {
    schema_digest: ContentDigest,
    call_ref: SemanticId,
    result_digest: ContentDigest,
    transcript_digest: ContentDigest,
    verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct CliResponse {
    profile: String,
    grade: String,
    operation: String,
    status: ResponseStatus,
    schema: Option<ProviderNeutralToolSchema>,
    outcome: Option<FakeControllerOutcome>,
    verification: Option<VerificationRecord>,
    faults: Vec<CliFault>,
    residuals: Vec<String>,
}

impl CliResponse {
    fn empty(operation: impl Into<String>, status: ResponseStatus) -> Self {
        Self {
            profile: RESPONSE_PROFILE.to_owned(),
            grade: RELEASE_GRADE.to_owned(),
            operation: operation.into(),
            status,
            schema: None,
            outcome: None,
            verification: None,
            faults: Vec::new(),
            residuals: vec![
                "no model or provider was called".to_owned(),
                "no external semantic effect was performed".to_owned(),
                "this result is not production qualification".to_owned(),
            ],
        }
    }

    fn fault(
        operation: impl Into<String>,
        status: ResponseStatus,
        code: impl Into<String>,
        stage: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        let mut response = Self::empty(operation, status);
        response.faults.push(CliFault {
            code: code.into(),
            stage: stage.into(),
            message: bounded(message.as_ref()),
        });
        response
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    schema: ProviderNeutralToolSchema,
    proposal: ToolCallProposal,
    lane: AuthorshipLaneEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    schema: ProviderNeutralToolSchema,
    proposal: ToolCallProposal,
    lane: AuthorshipLaneEvidence,
    outcome: FakeControllerOutcome,
}

fn main() -> ExitCode {
    let response = dispatch(env::args().skip(1).collect());
    let exit_code = response.status.exit_code();
    if let Some(fault) = response.faults.first() {
        eprintln!(
            "cantor-procedure-experiment: {} at {}",
            fault.code, fault.stage
        );
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &response).is_err() || writeln!(output).is_err() {
        let fallback = concat!(
            "{\"profile\":\"cantor-procedure-tool-cli/0.1\",",
            "\"grade\":\"effectless_internal_experiment_only\",",
            "\"operation\":\"unavailable\",\"status\":\"internal_fault\",",
            "\"schema\":null,\"outcome\":null,\"verification\":null,",
            "\"faults\":[{\"code\":\"response_serialization_failed\",",
            "\"stage\":\"output\",\"message\":\"failed to serialize response\"}],",
            "\"residuals\":[\"no model or provider was called\",",
            "\"no external semantic effect was performed\",",
            "\"this result is not production qualification\"]}\n"
        );
        let _ = output.write_all(fallback.as_bytes());
        return ExitCode::from(ResponseStatus::InternalFault.exit_code());
    }
    ExitCode::from(exit_code)
}

fn dispatch(arguments: Vec<String>) -> CliResponse {
    let Some(command) = arguments.first().map(String::as_str) else {
        return invalid_arguments("unavailable", "missing command");
    };
    match command {
        "schema" => {
            if arguments.len() != 1 {
                return invalid_arguments("schema", "schema accepts no arguments");
            }
            match provider_neutral_exchange_schema() {
                Ok(schema) => {
                    let mut response = CliResponse::empty("schema", ResponseStatus::Success);
                    response.schema = Some(schema);
                    response
                }
                Err(fault) => CliResponse::fault(
                    "schema",
                    ResponseStatus::InternalFault,
                    "schema_construction_failed",
                    "schema",
                    fault.to_string(),
                ),
            }
        }
        "run" => dispatch_run(&arguments[1..]),
        "verify" => dispatch_verify(&arguments[1..]),
        "help" | "--help" | "-h" => invalid_arguments(
            "unavailable",
            "usage: cantor-procedure-experiment <schema|run|verify> [--input <path>]",
        ),
        other => invalid_arguments(other, format!("unknown command {other:?}")),
    }
}

fn dispatch_run(arguments: &[String]) -> CliResponse {
    let bytes = match read_command_input("run", arguments) {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let request: RunRequest = match decode_request("run", &bytes) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let outcome =
        match run_fake_controller_exchange(&request.schema, &request.proposal, &request.lane) {
            Ok(outcome) => outcome,
            Err(fault) => {
                return CliResponse::fault(
                    "run",
                    ResponseStatus::InternalFault,
                    "controller_execution_failed",
                    "controller",
                    fault.to_string(),
                );
            }
        };
    if let Err(fault) =
        verify_fake_controller_outcome(&request.schema, &request.proposal, &request.lane, &outcome)
    {
        return CliResponse::fault(
            "run",
            ResponseStatus::VerificationFailure,
            "generated_outcome_verification_failed",
            "verification",
            fault.to_string(),
        );
    }
    let status = match outcome.result.disposition {
        ToolResultDisposition::Completed => ResponseStatus::Success,
        ToolResultDisposition::Refused => ResponseStatus::Refused,
    };
    let mut response = CliResponse::empty("run", status);
    if status == ResponseStatus::Refused {
        response.faults = outcome
            .result
            .faults
            .iter()
            .map(|fault| CliFault {
                code: fault.code.clone(),
                stage: fault.stage.clone(),
                message: bounded(&fault.message),
            })
            .collect();
    }
    response.outcome = Some(outcome);
    response
}

fn dispatch_verify(arguments: &[String]) -> CliResponse {
    let bytes = match read_command_input("verify", arguments) {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    let request: VerifyRequest = match decode_request("verify", &bytes) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    if let Err(fault) = verify_fake_controller_outcome(
        &request.schema,
        &request.proposal,
        &request.lane,
        &request.outcome,
    ) {
        return CliResponse::fault(
            "verify",
            ResponseStatus::VerificationFailure,
            "outcome_verification_failed",
            "verification",
            fault.to_string(),
        );
    }
    let mut response = CliResponse::empty("verify", ResponseStatus::Success);
    response.verification = Some(VerificationRecord {
        schema_digest: request.schema.schema_digest,
        call_ref: request.proposal.call_id,
        result_digest: request.outcome.result.result_digest,
        transcript_digest: request.outcome.transcript.transcript_digest,
        verified: true,
    });
    response
}

fn read_command_input(operation: &str, arguments: &[String]) -> Result<Vec<u8>, Box<CliResponse>> {
    let input = parse_input_path(operation, arguments)?;
    let reader: Box<dyn Read> = match input.as_deref() {
        Some(path) => match File::open(path) {
            Ok(file) => Box::new(file),
            Err(error) => {
                return Err(Box::new(CliResponse::fault(
                    operation,
                    ResponseStatus::InvalidInput,
                    "input_read_failed",
                    "transport",
                    format!("cannot open input file {}: {error}", path.display()),
                )));
            }
        },
        None => Box::new(io::stdin().lock()),
    };
    read_bounded(operation, reader)
}

fn parse_input_path(
    operation: &str,
    arguments: &[String],
) -> Result<Option<PathBuf>, Box<CliResponse>> {
    match arguments {
        [] => Ok(None),
        [flag, value] if flag == "--input" && !value.is_empty() => Ok(Some(PathBuf::from(value))),
        [flag, _] if flag == "--input" => Err(Box::new(invalid_arguments(
            operation,
            "--input requires a nonempty path",
        ))),
        _ => Err(Box::new(invalid_arguments(
            operation,
            "expected no arguments or exactly --input <path>",
        ))),
    }
}

fn read_bounded(operation: &str, reader: impl Read) -> Result<Vec<u8>, Box<CliResponse>> {
    let mut bytes = Vec::new();
    if let Err(error) = reader.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes) {
        return Err(Box::new(CliResponse::fault(
            operation,
            ResponseStatus::InvalidInput,
            "input_read_failed",
            "transport",
            error.to_string(),
        )));
    }
    if bytes.is_empty() {
        return Err(Box::new(CliResponse::fault(
            operation,
            ResponseStatus::InvalidInput,
            "empty_input",
            "transport",
            "input is empty",
        )));
    }
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Box::new(CliResponse::fault(
            operation,
            ResponseStatus::InvalidInput,
            "input_limit_exceeded",
            "transport",
            format!("input exceeds the {MAX_INPUT_BYTES}-byte local limit"),
        )));
    }
    Ok(bytes)
}

fn decode_request<T: DeserializeOwned>(
    operation: &str,
    bytes: &[u8],
) -> Result<T, Box<CliResponse>> {
    serde_json::from_slice(bytes).map_err(|error| {
        Box::new(CliResponse::fault(
            operation,
            ResponseStatus::InvalidInput,
            "invalid_request_json",
            "decode",
            error.to_string(),
        ))
    })
}

fn invalid_arguments(operation: impl Into<String>, message: impl AsRef<str>) -> CliResponse {
    CliResponse::fault(
        operation,
        ResponseStatus::InvalidInput,
        "invalid_arguments",
        "arguments",
        message,
    )
}

fn bounded(message: &str) -> String {
    message.chars().take(MAX_MESSAGE_CHARS).collect()
}
