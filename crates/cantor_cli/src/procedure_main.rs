//! Bounded process adapter for the effectless Cantor procedure experiment.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use cantor_procedure_tool::{
    PrepareRequest, PreparedRunRequest, ProcedureToolResponse, ProcedureToolResponseStatus,
    VerifyRequest, prepare_response, run_response, schema_response, verify_response,
};
use serde::de::DeserializeOwned;

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

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
        return ExitCode::from(ProcedureToolResponseStatus::InternalFault.exit_code());
    }
    ExitCode::from(exit_code)
}

fn dispatch(arguments: Vec<String>) -> ProcedureToolResponse {
    let Some(command) = arguments.first().map(String::as_str) else {
        return invalid_arguments("unavailable", "missing command");
    };
    match command {
        "schema" => {
            if arguments.len() != 1 {
                return invalid_arguments("schema", "schema accepts no arguments");
            }
            schema_response()
        }
        "prepare" => dispatch_prepare(&arguments[1..]),
        "run" => dispatch_run(&arguments[1..]),
        "verify" => dispatch_verify(&arguments[1..]),
        "help" | "--help" | "-h" => invalid_arguments(
            "unavailable",
            "usage: cantor-procedure-experiment <schema|prepare|run|verify> [--input <path>]",
        ),
        other => invalid_arguments(other, format!("unknown command {other:?}")),
    }
}

fn dispatch_prepare(arguments: &[String]) -> ProcedureToolResponse {
    let bytes = match read_command_input("prepare", arguments) {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    match decode_request::<PrepareRequest>("prepare", &bytes) {
        Ok(request) => prepare_response(request),
        Err(response) => *response,
    }
}

fn dispatch_run(arguments: &[String]) -> ProcedureToolResponse {
    let bytes = match read_command_input("run", arguments) {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    match decode_request::<PreparedRunRequest>("run", &bytes) {
        Ok(request) => run_response(request),
        Err(response) => *response,
    }
}

fn dispatch_verify(arguments: &[String]) -> ProcedureToolResponse {
    let bytes = match read_command_input("verify", arguments) {
        Ok(bytes) => bytes,
        Err(response) => return *response,
    };
    match decode_request::<VerifyRequest>("verify", &bytes) {
        Ok(request) => verify_response(request),
        Err(response) => *response,
    }
}

fn read_command_input(
    operation: &str,
    arguments: &[String],
) -> Result<Vec<u8>, Box<ProcedureToolResponse>> {
    let input = parse_input_path(operation, arguments)?;
    let reader: Box<dyn Read> = match input.as_deref() {
        Some(path) => match File::open(path) {
            Ok(file) => Box::new(file),
            Err(error) => {
                return Err(Box::new(ProcedureToolResponse::fault(
                    operation,
                    ProcedureToolResponseStatus::InvalidInput,
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
) -> Result<Option<PathBuf>, Box<ProcedureToolResponse>> {
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

fn read_bounded(operation: &str, reader: impl Read) -> Result<Vec<u8>, Box<ProcedureToolResponse>> {
    let mut bytes = Vec::new();
    if let Err(error) = reader.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes) {
        return Err(Box::new(ProcedureToolResponse::fault(
            operation,
            ProcedureToolResponseStatus::InvalidInput,
            "input_read_failed",
            "transport",
            error.to_string(),
        )));
    }
    if bytes.is_empty() {
        return Err(Box::new(ProcedureToolResponse::fault(
            operation,
            ProcedureToolResponseStatus::InvalidInput,
            "empty_input",
            "transport",
            "input is empty",
        )));
    }
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(Box::new(ProcedureToolResponse::fault(
            operation,
            ProcedureToolResponseStatus::InvalidInput,
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
) -> Result<T, Box<ProcedureToolResponse>> {
    serde_json::from_slice(bytes).map_err(|error| {
        Box::new(ProcedureToolResponse::fault(
            operation,
            ProcedureToolResponseStatus::InvalidInput,
            "invalid_request_json",
            "decode",
            error.to_string(),
        ))
    })
}

fn invalid_arguments(
    operation: impl Into<String>,
    message: impl AsRef<str>,
) -> ProcedureToolResponse {
    ProcedureToolResponse::fault(
        operation,
        ProcedureToolResponseStatus::InvalidInput,
        "invalid_arguments",
        "arguments",
        message,
    )
}
