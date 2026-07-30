use std::{env, path::PathBuf};

use cantor_mcp::{CantorMcpServer, load_environment_file};
use rmcp::{ServiceExt, transport::stdio};

fn environment_path() -> Result<PathBuf, String> {
    let mut arguments = env::args_os().skip(1);
    match (
        arguments.next().and_then(|value| value.into_string().ok()),
        arguments.next(),
        arguments.next(),
    ) {
        (Some(flag), Some(path), None) if flag == "--environment" => Ok(PathBuf::from(path)),
        _ => Err("usage: cantor-mcp --environment <embedded-environment.json>".to_owned()),
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
    let path = environment_path()?;
    let environment = load_environment_file(&path)?;
    let server = CantorMcpServer::new(environment)?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
