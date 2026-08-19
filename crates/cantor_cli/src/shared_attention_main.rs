//! JSON transport shell for the pure shared-attention runtime.

use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use cantor_core::{
    SharedAttentionToolRequest, SharedAttentionToolResponse, execute_shared_attention_tool_request,
};

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;

fn main() -> ExitCode {
    let response = dispatch(env::args().skip(1).collect());
    if let Some(fault) = &response.fault {
        eprintln!("cantor-shared-attention: {}: {}", fault.code, fault.message);
    }
    let exit_code = response.exit_code();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &response).is_err() || writeln!(output).is_err() {
        eprintln!("cantor-shared-attention: response serialization failed");
        return ExitCode::from(4);
    }
    ExitCode::from(exit_code)
}

fn dispatch(arguments: Vec<String>) -> SharedAttentionToolResponse {
    let input_path = match parse_arguments(&arguments) {
        Ok(path) => path,
        Err(message) => {
            return SharedAttentionToolResponse::invalid_request("invalid_arguments", message);
        }
    };
    let bytes = match read_bounded_input(input_path.as_ref()) {
        Ok(bytes) => bytes,
        Err(message) => {
            return SharedAttentionToolResponse::invalid_request("input_read_failure", message);
        }
    };
    let request: SharedAttentionToolRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(error) => {
            return SharedAttentionToolResponse::invalid_request(
                "malformed_request",
                format!("input is not a valid closed request: {error}"),
            );
        }
    };
    execute_shared_attention_tool_request(request)
}

fn parse_arguments(arguments: &[String]) -> Result<Option<PathBuf>, String> {
    match arguments {
        [] => Ok(None),
        [flag, path] if flag == "--input" && !path.is_empty() => Ok(Some(PathBuf::from(path))),
        [flag] if matches!(flag.as_str(), "help" | "--help" | "-h") => Err(
            "usage: cantor-shared-attention [--input <path>]; omit --input to read one request JSON object from stdin"
                .to_owned(),
        ),
        _ => Err("expected no arguments or exactly --input <path>".to_owned()),
    }
}

fn read_bounded_input(path: Option<&PathBuf>) -> Result<Vec<u8>, String> {
    let reader: Box<dyn Read> = match path {
        Some(path) => Box::new(
            File::open(path)
                .map_err(|error| format!("cannot open input {}: {error}", path.display()))?,
        ),
        None => Box::new(io::stdin().lock()),
    };
    let mut bytes = Vec::new();
    reader
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read input: {error}"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("input exceeds {MAX_INPUT_BYTES} bytes"));
    }
    if bytes.is_empty() {
        return Err("input is empty".to_owned());
    }
    Ok(bytes)
}
