use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use cantor_core::{
    EmbeddedRuntimeEnvironment, ExitClass, ProtocolRequest, ProtocolResponse, SemanticId,
    execute_protocol_request,
};

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

fn main() -> ExitCode {
    let (response, diagnostic) = dispatch(env::args().skip(1).collect());
    if let Some(diagnostic) = diagnostic {
        eprintln!("cantor: {diagnostic}");
    }
    let exit_class = response.exit_class;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &response).is_err() || writeln!(output).is_err() {
        eprintln!("cantor: internal_fault: failed to serialize protocol response");
        return ExitCode::from(ExitClass::InternalFault.code());
    }
    ExitCode::from(exit_class.code())
}

fn dispatch(arguments: Vec<String>) -> (ProtocolResponse, Option<String>) {
    let Some(command) = arguments.first().map(String::as_str) else {
        return transport_fault(
            "unknown",
            ExitClass::InvalidRequest,
            "missing_command",
            "expected `cantor query` or `cantor inspect`",
        );
    };
    if matches!(command, "help" | "--help" | "-h") {
        return transport_fault(
            "help",
            ExitClass::InvalidRequest,
            "help_requested",
            "usage: cantor <query|inspect> --environment <path> [--input <path>]; omit --input to read request JSON from stdin",
        );
    }
    if !matches!(command, "query" | "inspect") {
        return transport_fault(
            command,
            ExitClass::InvalidRequest,
            "unknown_command",
            format!("unknown command {command:?}; expected query or inspect"),
        );
    }
    let paths = match parse_paths(&arguments[1..]) {
        Ok(paths) => paths,
        Err(message) => {
            return transport_fault(
                command,
                ExitClass::InvalidRequest,
                "invalid_arguments",
                message,
            );
        }
    };
    let environment_bytes = match read_bounded_file(&paths.environment) {
        Ok(bytes) => bytes,
        Err(message) => {
            return transport_fault(
                command,
                ExitClass::TrustFailure,
                "environment_read_failure",
                message,
            );
        }
    };
    let environment: EmbeddedRuntimeEnvironment = match serde_json::from_slice(&environment_bytes) {
        Ok(environment) => environment,
        Err(error) => {
            return transport_fault(
                command,
                ExitClass::TrustFailure,
                "malformed_environment",
                format!("runtime environment is not valid JSON: {error}"),
            );
        }
    };
    let bytes = match read_bounded_input(paths.input.as_ref()) {
        Ok(bytes) => bytes,
        Err(message) => {
            return transport_fault(
                command,
                ExitClass::InvalidRequest,
                "input_read_failure",
                message,
            );
        }
    };
    let request: ProtocolRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(error) => {
            return transport_fault(
                command,
                ExitClass::InvalidRequest,
                "malformed_json",
                format!("request is not valid protocol JSON: {error}"),
            );
        }
    };
    if request.request.name() != command {
        let response = ProtocolResponse::transport_fault(
            request.request_id,
            command,
            ExitClass::InvalidRequest,
            "operation_command_mismatch",
            format!(
                "command {command:?} does not match envelope operation {:?}",
                request.request.name()
            ),
        );
        return (
            response,
            Some("invalid_request: operation_command_mismatch".to_owned()),
        );
    }
    let response = execute_protocol_request(&environment, request);
    let diagnostic = response.faults.first().map(|fault| {
        format!(
            "{:?}: {} at {}",
            response.exit_class, fault.code, fault.stage
        )
    });
    (response, diagnostic)
}

struct InvocationPaths {
    environment: PathBuf,
    input: Option<PathBuf>,
}

fn parse_paths(arguments: &[String]) -> Result<InvocationPaths, String> {
    let mut environment = None;
    let mut input = None;
    let mut position = 0;
    while position < arguments.len() {
        let flag = &arguments[position];
        let value = arguments
            .get(position + 1)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{flag} requires a nonempty path"))?;
        match flag.as_str() {
            "--environment" if environment.is_none() => {
                environment = Some(PathBuf::from(value));
            }
            "--input" if input.is_none() => {
                input = Some(PathBuf::from(value));
            }
            "--environment" | "--input" => {
                return Err(format!("{flag} may be supplied only once"));
            }
            _ => return Err(format!("unknown argument {flag:?}")),
        }
        position += 2;
    }
    let environment = environment.ok_or_else(|| "--environment <path> is required".to_owned())?;
    Ok(InvocationPaths { environment, input })
}

fn read_bounded_input(path: Option<&PathBuf>) -> Result<Vec<u8>, String> {
    let reader: Box<dyn Read> = match path {
        Some(path) => {
            let file = File::open(path)
                .map_err(|error| format!("cannot open input file {}: {error}", path.display()))?;
            Box::new(file)
        }
        None => Box::new(io::stdin().lock()),
    };
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read protocol input: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "protocol input exceeds the {MAX_INPUT_BYTES}-byte local limit"
        ));
    }
    if bytes.is_empty() {
        return Err("protocol input is empty".to_owned());
    }
    Ok(bytes)
}

fn read_bounded_file(path: &PathBuf) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| {
        format!(
            "cannot open runtime environment {}: {error}",
            path.display()
        )
    })?;
    read_bounded_reader(file, "runtime environment")
}

fn read_bounded_reader(reader: impl Read, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "{label} exceeds the {MAX_INPUT_BYTES}-byte local limit"
        ));
    }
    if bytes.is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(bytes)
}

fn transport_fault(
    operation: impl Into<String>,
    class: ExitClass,
    code: impl Into<String>,
    message: impl Into<String>,
) -> (ProtocolResponse, Option<String>) {
    let code = code.into();
    let response = ProtocolResponse::transport_fault(
        unavailable_request_id(),
        operation,
        class,
        code.clone(),
        message,
    );
    (response, Some(format!("{class:?}: {code}")))
}

fn unavailable_request_id() -> SemanticId {
    SemanticId::new("request:unavailable")
        .unwrap_or_else(|_| unreachable!("static protocol fallback identity is valid"))
}
