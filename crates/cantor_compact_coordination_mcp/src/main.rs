use std::env;

use cantor_compact_coordination_mcp::CompactCoordinationMcpServer;
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cantor-compact-coordination-mcp: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().nth(1).is_some() {
        return Err("usage: cantor-compact-coordination-mcp".into());
    }
    let server = CompactCoordinationMcpServer::local()?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
