use std::env;

use cantor_attention_ledger_mcp::AttentionLedgerMcpServer;
use cantor_core::SemanticId;
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cantor-attention-ledger-mcp: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let ledger_id = match (arguments.next(), arguments.next(), arguments.next()) {
        (Some(flag), Some(value), None) if flag == "--ledger-id" => SemanticId::new(value)?,
        _ => return Err("usage: cantor-attention-ledger-mcp --ledger-id <semantic-id>".into()),
    };
    let server = AttentionLedgerMcpServer::new(ledger_id)?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
