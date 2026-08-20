//! Provider-free JSON shell for native lifecycle coherence replay.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use cantor_core::{
    NATIVE_LIFECYCLE_MAX_INPUT_BYTES, NATIVE_LIFECYCLE_MAX_RESPONSE_BYTES,
    NATIVE_LIFECYCLE_VALIDATION_PROTOCOL, NativeLifecycleValidationFaultKind,
    NativeLifecycleValidationResponse, validate_native_lifecycle_json,
};

const USAGE: &str = "usage: cantor-compiler-lab [--input <path>]\n       cantor-compiler-lab --help\n       cantor-compiler-lab --version\n\nomit --input to read one strict native lifecycle validation request from stdin";

fn main() -> ExitCode {
    match parse_arguments(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("cantor-compiler-lab {NATIVE_LIFECYCLE_VALIDATION_PROTOCOL}");
            ExitCode::SUCCESS
        }
        Ok(Command::Validate(path)) => emit_response(dispatch(path.as_ref())),
        Err(detail) => emit_response(NativeLifecycleValidationResponse::input_refused(
            NativeLifecycleValidationFaultKind::Wire,
            "arguments",
            detail,
        )),
    }
}

enum Command {
    Help,
    Version,
    Validate(Option<PathBuf>),
}

fn parse_arguments(arguments: &[String]) -> Result<Command, String> {
    match arguments {
        [] => Ok(Command::Validate(None)),
        [flag] if matches!(flag.as_str(), "help" | "--help" | "-h") => Ok(Command::Help),
        [flag] if matches!(flag.as_str(), "version" | "--version" | "-V") => Ok(Command::Version),
        [flag, path] if flag == "--input" && !path.is_empty() => {
            Ok(Command::Validate(Some(PathBuf::from(path))))
        }
        _ => {
            Err("expected no arguments or exactly --input <path>, --help, or --version".to_owned())
        }
    }
}

fn dispatch(input_path: Option<&PathBuf>) -> NativeLifecycleValidationResponse {
    let bytes = match read_bounded_input(input_path) {
        Ok(bytes) => bytes,
        Err((kind, detail)) => {
            return NativeLifecycleValidationResponse::input_refused(kind, "input", detail);
        }
    };
    validate_native_lifecycle_json(&bytes)
}

fn read_bounded_input(
    path: Option<&PathBuf>,
) -> Result<Vec<u8>, (NativeLifecycleValidationFaultKind, String)> {
    let reader: Box<dyn Read> = match path {
        Some(path) => Box::new(File::open(path).map_err(|error| {
            (
                NativeLifecycleValidationFaultKind::Wire,
                format!("cannot open input {}: {error}", path.display()),
            )
        })?),
        None => Box::new(io::stdin().lock()),
    };
    let mut bytes = Vec::new();
    reader
        .take(NATIVE_LIFECYCLE_MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            (
                NativeLifecycleValidationFaultKind::Wire,
                format!("cannot read input: {error}"),
            )
        })?;
    if bytes.len() > NATIVE_LIFECYCLE_MAX_INPUT_BYTES {
        return Err((
            NativeLifecycleValidationFaultKind::InvalidBound,
            format!("input exceeds {NATIVE_LIFECYCLE_MAX_INPUT_BYTES} bytes"),
        ));
    }
    if bytes.is_empty() {
        return Err((
            NativeLifecycleValidationFaultKind::Wire,
            "input is empty".to_owned(),
        ));
    }
    Ok(bytes)
}

fn emit_response(response: NativeLifecycleValidationResponse) -> ExitCode {
    let exit_code = response.exit_code();
    let bytes = match serde_json::to_vec(&response) {
        Ok(bytes) if bytes.len() <= NATIVE_LIFECYCLE_MAX_RESPONSE_BYTES => bytes,
        Ok(_) => {
            eprintln!("cantor-compiler-lab: response exceeds the protocol output bound");
            return ExitCode::from(70);
        }
        Err(error) => {
            eprintln!("cantor-compiler-lab: response serialization failed: {error}");
            return ExitCode::from(70);
        }
    };
    if let Some(fault) = response.faults.first() {
        eprintln!(
            "cantor-compiler-lab: {:?}: {}: {}",
            fault.kind, fault.field, fault.detail
        );
    }
    let mut stdout = io::stdout().lock();
    if stdout
        .write_all(&bytes)
        .and_then(|()| stdout.write_all(b"\n"))
        .is_err()
    {
        eprintln!("cantor-compiler-lab: response write failed");
        return ExitCode::from(70);
    }
    ExitCode::from(exit_code)
}
