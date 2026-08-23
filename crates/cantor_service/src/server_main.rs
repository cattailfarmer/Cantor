use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use cantor_service::{BoundServer, ConfigurationDiagnosticStatus, diagnose_service_configuration};

const USAGE: &str = "usage: cantord --config <absolute-service-config.json> | cantord --check-config <absolute-service-config.json>";

fn main() -> ExitCode {
    let invocation = match parse_invocation() {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("cantord: {error}");
            return ExitCode::from(2);
        }
    };
    match invocation {
        Invocation::Serve(config_path) => serve(config_path),
        Invocation::CheckConfig(config_path) => check_config(config_path),
    }
}

enum Invocation {
    Serve(PathBuf),
    CheckConfig(PathBuf),
}

fn parse_invocation() -> Result<Invocation, &'static str> {
    let mut arguments = env::args_os().skip(1);
    match (arguments.next(), arguments.next(), arguments.next()) {
        (Some(flag), Some(path), None) if flag == "--config" => {
            Ok(Invocation::Serve(PathBuf::from(path)))
        }
        (Some(flag), Some(path), None) if flag == "--check-config" => {
            Ok(Invocation::CheckConfig(PathBuf::from(path)))
        }
        _ => Err(USAGE),
    }
}

fn serve(config_path: PathBuf) -> ExitCode {
    match BoundServer::bind(&config_path).and_then(|server| {
        eprintln!("cantord: listening on {}", server.local_addr()?);
        server.serve()
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cantord: {error}");
            ExitCode::from(2)
        }
    }
}

fn check_config(config_path: PathBuf) -> ExitCode {
    let diagnostic = diagnose_service_configuration(&config_path);
    let status = diagnostic.status;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &diagnostic).is_err() || writeln!(output).is_err() {
        eprintln!("cantord: failed to serialize configuration diagnostic");
        return ExitCode::from(70);
    }
    match status {
        ConfigurationDiagnosticStatus::Ready => ExitCode::SUCCESS,
        ConfigurationDiagnosticStatus::Refused => ExitCode::from(3),
    }
}
