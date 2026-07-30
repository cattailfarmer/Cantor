use std::{env, path::PathBuf};

use cantor_mcp::{CantorMcpServer, load_environment_file};
use rmcp::{ServiceExt, transport::stdio};

enum StartupMode {
    Embedded(PathBuf),
    Resident(PathBuf),
}

fn startup_mode() -> Result<StartupMode, String> {
    let mut arguments = env::args_os().skip(1);
    match (
        arguments.next().and_then(|value| value.into_string().ok()),
        arguments.next(),
        arguments.next(),
    ) {
        (Some(flag), Some(path), None) if flag == "--environment" => {
            Ok(StartupMode::Embedded(PathBuf::from(path)))
        }
        (Some(flag), Some(path), None) if flag == "--service-config" => {
            Ok(StartupMode::Resident(PathBuf::from(path)))
        }
        _ => Err(
            "usage: cantor-mcp (--environment <embedded-environment.json> | --service-config <absolute-service-config.json>)"
                .to_owned(),
        ),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cantor-mcp: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let server = match startup_mode()? {
        StartupMode::Embedded(path) => {
            let environment = load_environment_file(&path)?;
            CantorMcpServer::new(environment)?
        }
        StartupMode::Resident(path) => CantorMcpServer::from_service_config(&path)?,
    };
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
