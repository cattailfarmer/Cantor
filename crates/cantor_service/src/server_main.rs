use std::{env, path::PathBuf, process::ExitCode};

use cantor_service::BoundServer;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cantord: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let config_path = match (arguments.next(), arguments.next(), arguments.next()) {
        (Some(flag), Some(path), None) if flag == "--config" => PathBuf::from(path),
        _ => return Err("usage: cantord --config <absolute-service-config.json>".into()),
    };
    let server = BoundServer::bind(&config_path)?;
    eprintln!("cantord: listening on {}", server.local_addr()?);
    server.serve()?;
    Ok(())
}
