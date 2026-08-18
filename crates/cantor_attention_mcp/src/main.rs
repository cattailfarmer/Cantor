use std::{env, path::PathBuf};

use cantor_attention_mcp::{AttentionMcpServer, load_config_file};
use rmcp::{ServiceExt, transport::stdio};

fn config_path() -> Result<PathBuf, String> {
    let mut arguments = env::args_os().skip(1);
    match (
        arguments.next().and_then(|value| value.into_string().ok()),
        arguments.next(),
        arguments.next(),
    ) {
        (Some(flag), Some(path), None) if flag == "--config" => Ok(PathBuf::from(path)),
        _ => Err("usage: cantor-attention-mcp --config <absolute-config.json>".to_owned()),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cantor-attention-mcp: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config_file(&config_path()?)?;
    let server = AttentionMcpServer::new(config).await?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
