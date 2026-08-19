use std::env;

use cantor_shared_attention_mcp::SharedAttentionMcpServer;
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cantor-shared-attention-mcp: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().nth(1).is_some() {
        return Err("usage: cantor-shared-attention-mcp".into());
    }
    let service = SharedAttentionMcpServer.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
