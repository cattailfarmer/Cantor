use std::env;

use cantor_compiler_mcp::CompilerMcpServer;
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cantor-compiler-mcp: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().nth(1).is_some() {
        return Err("usage: cantor-compiler-mcp".into());
    }
    let service = CompilerMcpServer.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
