use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use cantor_core::{ContentDigest, ProtocolRequest, SemanticId};
use cantor_service::{
    ServiceFault, ServiceOperation, ServiceResponse, response_exit_code, send_request,
    unavailable_request_id,
};

const MAX_INPUT_BYTES: usize = 1024 * 1024;

fn main() -> ExitCode {
    let (response, diagnostic) = dispatch(env::args().skip(1).collect());
    if let Some(diagnostic) = diagnostic {
        eprintln!("cantorctl: {diagnostic}");
    }
    let exit = response_exit_code(&response);
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &response).is_err() || writeln!(output).is_err() {
        eprintln!("cantorctl: failed to serialize service response");
        return ExitCode::from(70);
    }
    ExitCode::from(exit)
}

fn dispatch(arguments: Vec<String>) -> (ServiceResponse, Option<String>) {
    match build_invocation(arguments).and_then(|invocation| {
        send_request(
            &invocation.config_path,
            invocation.operation,
            invocation.request_id,
        )
    }) {
        Ok(response) => {
            let diagnostic = response.faults.first().map(ToString::to_string);
            (response, diagnostic)
        }
        Err(fault) => {
            let diagnostic = fault.to_string();
            (
                ServiceResponse::fault(unavailable_request_id(), None, fault),
                Some(diagnostic),
            )
        }
    }
}

struct ClientInvocation {
    config_path: PathBuf,
    request_id: SemanticId,
    operation: ServiceOperation,
}

fn build_invocation(arguments: Vec<String>) -> Result<ClientInvocation, ServiceFault> {
    let command = arguments.first().ok_or_else(|| {
        ServiceFault::new(
            "missing_command",
            "client_arguments",
            "expected status, query, inspect, refresh, or shutdown",
        )
    })?;
    if !matches!(
        command.as_str(),
        "status" | "query" | "inspect" | "refresh" | "shutdown"
    ) {
        return Err(ServiceFault::new(
            "unknown_command",
            "client_arguments",
            "expected status, query, inspect, refresh, or shutdown",
        ));
    }
    let flags = parse_flags(&arguments[1..])?;
    let config_path = required_path(&flags, "--config")?;
    let request_id = required_id(&flags, "--request-id")?;
    let operation = match command.as_str() {
        "status" => {
            require_exact_flags(&flags, &["--config", "--request-id"])?;
            ServiceOperation::Status
        }
        "query" | "inspect" => {
            require_allowed_flags(&flags, &["--config", "--request-id", "--input"])?;
            let bytes = read_input(flags.get("--input").map(PathBuf::from).as_ref())?;
            let request: ProtocolRequest = serde_json::from_slice(&bytes).map_err(|error| {
                ServiceFault::new(
                    "invalid_protocol_request",
                    "client_input",
                    format!("input is not valid strict Cantor protocol JSON: {error}"),
                )
            })?;
            if request.request.name() != command {
                return Err(ServiceFault::new(
                    "operation_command_mismatch",
                    "client_input",
                    format!(
                        "command {command:?} does not match protocol operation {:?}",
                        request.request.name()
                    ),
                ));
            }
            ServiceOperation::Execute {
                request: Box::new(request),
            }
        }
        "refresh" => {
            require_exact_flags(
                &flags,
                &[
                    "--config",
                    "--request-id",
                    "--expected-generation",
                    "--expected-sequence",
                ],
            )?;
            ServiceOperation::Refresh {
                expected_generation_id: required_digest(&flags, "--expected-generation")?,
                expected_activation_sequence: required_u64(&flags, "--expected-sequence")?,
            }
        }
        "shutdown" => {
            require_exact_flags(
                &flags,
                &["--config", "--request-id", "--expected-generation"],
            )?;
            ServiceOperation::Shutdown {
                expected_generation_id: required_digest(&flags, "--expected-generation")?,
            }
        }
        _ => unreachable!("command was validated"),
    };
    Ok(ClientInvocation {
        config_path,
        request_id,
        operation,
    })
}

fn parse_flags(arguments: &[String]) -> Result<BTreeMap<String, String>, ServiceFault> {
    if !arguments.len().is_multiple_of(2) {
        return Err(ServiceFault::new(
            "invalid_arguments",
            "client_arguments",
            "every flag requires one nonempty value",
        ));
    }
    let mut flags = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        if !pair[0].starts_with("--") || pair[1].is_empty() {
            return Err(ServiceFault::new(
                "invalid_arguments",
                "client_arguments",
                "every flag requires one nonempty value",
            ));
        }
        if flags.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(ServiceFault::new(
                "duplicate_argument",
                "client_arguments",
                format!("{} may be supplied only once", pair[0]),
            ));
        }
    }
    Ok(flags)
}

fn require_exact_flags(
    flags: &BTreeMap<String, String>,
    expected: &[&str],
) -> Result<(), ServiceFault> {
    require_allowed_flags(flags, expected)?;
    for name in expected {
        if !flags.contains_key(*name) {
            return Err(ServiceFault::new(
                "missing_argument",
                "client_arguments",
                format!("{name} is required"),
            ));
        }
    }
    Ok(())
}

fn require_allowed_flags(
    flags: &BTreeMap<String, String>,
    allowed: &[&str],
) -> Result<(), ServiceFault> {
    if let Some(name) = flags.keys().find(|name| !allowed.contains(&name.as_str())) {
        return Err(ServiceFault::new(
            "unknown_argument",
            "client_arguments",
            format!("unknown argument {name:?}"),
        ));
    }
    Ok(())
}

fn required_path(flags: &BTreeMap<String, String>, name: &str) -> Result<PathBuf, ServiceFault> {
    flags.get(name).map(PathBuf::from).ok_or_else(|| {
        ServiceFault::new(
            "missing_argument",
            "client_arguments",
            format!("{name} is required"),
        )
    })
}

fn required_id(flags: &BTreeMap<String, String>, name: &str) -> Result<SemanticId, ServiceFault> {
    let value = flags.get(name).ok_or_else(|| {
        ServiceFault::new(
            "missing_argument",
            "client_arguments",
            format!("{name} is required"),
        )
    })?;
    SemanticId::new(value.clone()).map_err(|error| {
        ServiceFault::new(
            "invalid_request_identity",
            "client_arguments",
            error.to_string(),
        )
    })
}

fn required_digest(
    flags: &BTreeMap<String, String>,
    name: &str,
) -> Result<ContentDigest, ServiceFault> {
    let value = flags.get(name).ok_or_else(|| {
        ServiceFault::new(
            "missing_argument",
            "client_arguments",
            format!("{name} is required"),
        )
    })?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ServiceFault::new(
            "invalid_digest",
            "client_arguments",
            format!("{name} must contain exactly 64 hexadecimal characters"),
        ));
    }
    Ok(ContentDigest {
        algorithm: "sha256".to_owned(),
        value: value.to_ascii_lowercase(),
    })
}

fn required_u64(flags: &BTreeMap<String, String>, name: &str) -> Result<u64, ServiceFault> {
    flags
        .get(name)
        .ok_or_else(|| {
            ServiceFault::new(
                "missing_argument",
                "client_arguments",
                format!("{name} is required"),
            )
        })?
        .parse()
        .map_err(|error| {
            ServiceFault::new(
                "invalid_integer",
                "client_arguments",
                format!("{name} is not a valid unsigned integer: {error}"),
            )
        })
}

fn read_input(path: Option<&PathBuf>) -> Result<Vec<u8>, ServiceFault> {
    let reader: Box<dyn Read> = match path {
        Some(path) => Box::new(File::open(path).map_err(|error| {
            ServiceFault::new(
                "input_read_failed",
                "client_input",
                format!("cannot open input file: {error}"),
            )
        })?),
        None => Box::new(io::stdin().lock()),
    };
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ServiceFault::new(
                "input_read_failed",
                "client_input",
                format!("cannot read protocol input: {error}"),
            )
        })?;
    if bytes.is_empty() {
        return Err(ServiceFault::new(
            "empty_input",
            "client_input",
            "protocol input is empty",
        ));
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ServiceFault::new(
            "input_limit_exceeded",
            "client_input",
            "protocol input exceeds the local client limit",
        ));
    }
    Ok(bytes)
}
