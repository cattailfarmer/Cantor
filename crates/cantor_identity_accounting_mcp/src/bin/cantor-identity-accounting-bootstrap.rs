use std::{env, io::Write, path::PathBuf};

use cantor_core::SemanticId;
use cantor_identity_accounting_mcp::{
    BootstrapStoreConfig, SnapshotStoreConfig, bootstrap_identity_accounting_store,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("cantor-identity-accounting-bootstrap: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let values = env::args().skip(1).collect::<Vec<_>>();
    if values.len() != 12
        || values[0] != "--store-dir"
        || values[2] != "--ledger-file"
        || values[4] != "--journal-id"
        || values[6] != "--max-ledger-bytes"
        || values[8] != "--max-snapshot-bytes"
        || values[10] != "--max-snapshots"
    {
        return Err("usage: cantor-identity-accounting-bootstrap --store-dir <absent-path> --ledger-file <canonical-ledger.json> --journal-id <semantic-id> --max-ledger-bytes <u64> --max-snapshot-bytes <u64> --max-snapshots <usize>".into());
    }
    let receipt = bootstrap_identity_accounting_store(BootstrapStoreConfig {
        store: SnapshotStoreConfig {
            directory: PathBuf::from(&values[1]),
            journal_id: SemanticId::new(values[5].clone())?,
            maximum_snapshot_bytes: values[9].parse()?,
            maximum_snapshots: values[11].parse()?,
        },
        ledger_file: PathBuf::from(&values[3]),
        maximum_ledger_bytes: values[7].parse()?,
    })?;
    let mut encoded = serde_json::to_vec(&receipt)?;
    encoded.push(b'\n');
    std::io::stdout().lock().write_all(&encoded)?;
    Ok(())
}
