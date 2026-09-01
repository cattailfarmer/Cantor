use std::{env, path::PathBuf};

use cantor_core::SemanticId;
use cantor_identity_accounting_mcp::{IdentityAccountingMcpServer, SnapshotStoreConfig};
use rmcp::{ServiceExt, transport::stdio};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("cantor-identity-accounting-mcp: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let values = env::args().skip(1).collect::<Vec<_>>();
    if values.len() != 8
        || values[0] != "--store-dir"
        || values[2] != "--journal-id"
        || values[4] != "--max-snapshot-bytes"
        || values[6] != "--max-snapshots"
    {
        return Err("usage: cantor-identity-accounting-mcp --store-dir <path> --journal-id <semantic-id> --max-snapshot-bytes <u64> --max-snapshots <usize>".into());
    }
    let server = IdentityAccountingMcpServer::open(SnapshotStoreConfig {
        directory: PathBuf::from(&values[1]),
        journal_id: SemanticId::new(values[3].clone())?,
        maximum_snapshot_bytes: values[5].parse()?,
        maximum_snapshots: values[7].parse()?,
    })?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
