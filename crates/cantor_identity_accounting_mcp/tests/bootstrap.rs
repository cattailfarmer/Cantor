use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    AccountableObject, ContentDigest, IdentityLedger, SemanticId, finalize_accountable_object,
    new_identity_ledger,
};
use cantor_identity_accounting_mcp::{
    BOOTSTRAP_RECEIPT_PROFILE, BootstrapReceipt, BootstrapStoreConfig, IdentityAccountingMcpServer,
    SnapshotStoreConfig, bootstrap_identity_accounting_store,
};

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cantor-identity-bootstrap-{label}-{}-{}",
            std::process::id(),
            DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn absent_child(&self, label: &str) -> PathBuf {
        self.0.join(label)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        if self.0.is_dir() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).unwrap()
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn ledger() -> IdentityLedger {
    let object = finalize_accountable_object(AccountableObject {
        profile: "cantor-accountable-object/0.1".to_owned(),
        handle: sid("object:airplane/alpha"),
        object_type: sid("airplane"),
        labels: BTreeSet::from(["the first airplane".to_owned()]),
        differentiators: BTreeMap::from([("tail_number".to_owned(), "N100AA".to_owned())]),
        state: BTreeMap::from([("readiness".to_owned(), "ready".to_owned())]),
        roles: BTreeSet::from([sid("role:transport")]),
        purposes: BTreeSet::from([sid("purpose:test-accounting")]),
        obligations: BTreeSet::from([sid("obligation:retain-identity")]),
        provenance_refs: BTreeSet::from([sid("source:bootstrap-fixture")]),
        version: 1,
        record_digest: empty_digest(),
    })
    .unwrap();
    new_identity_ledger(sid("basket:bootstrap-fixture"), vec![object]).unwrap()
}

fn write_ledger(directory: &Path, bytes: &[u8]) -> PathBuf {
    let path = directory.join("ledger.json");
    fs::write(&path, bytes).unwrap();
    path
}

fn config(root: &TempDirectory, ledger_file: PathBuf, store_label: &str) -> BootstrapStoreConfig {
    BootstrapStoreConfig {
        store: SnapshotStoreConfig {
            directory: root.absent_child(store_label),
            journal_id: sid("journal:bootstrap-fixture"),
            maximum_snapshot_bytes: 1024 * 1024,
            maximum_snapshots: 32,
        },
        ledger_file,
        maximum_ledger_bytes: 1024 * 1024,
    }
}

#[tokio::test]
async fn canonical_ledger_bootstraps_one_restartable_store_and_exact_receipt() {
    let root = TempDirectory::new("success");
    let initial = ledger();
    let input = write_ledger(&root.0, &serde_json::to_vec(&initial).unwrap());
    let bootstrap = config(&root, input, "store");
    let receipt = bootstrap_identity_accounting_store(bootstrap.clone()).unwrap();

    assert_eq!(receipt.profile, BOOTSTRAP_RECEIPT_PROFILE);
    assert_eq!(receipt.basket_id, initial.basket_id);
    assert_eq!(receipt.head_ledger_digest, initial.ledger_digest);
    assert_eq!(
        receipt.snapshot_filename,
        format!("{}.json", receipt.journal_digest.value)
    );
    assert!(
        bootstrap
            .store
            .directory
            .join(&receipt.snapshot_filename)
            .is_file()
    );

    let server = IdentityAccountingMcpServer::open(bootstrap.store).unwrap();
    let restored = server.snapshot().await;
    assert_eq!(restored.journal_digest, receipt.journal_digest);
    assert_eq!(restored.events[0].event_id, receipt.genesis_event_id);
    assert_eq!(restored.ledgers.len(), 1);
}

#[test]
fn existing_store_target_is_refused_without_mutating_its_contents() {
    let root = TempDirectory::new("existing");
    let input = write_ledger(&root.0, &serde_json::to_vec(&ledger()).unwrap());
    let bootstrap = config(&root, input, "store");
    fs::create_dir(&bootstrap.store.directory).unwrap();
    let sentinel = bootstrap.store.directory.join("operator-owned.txt");
    fs::write(&sentinel, b"preserve").unwrap();

    let fault = bootstrap_identity_accounting_store(bootstrap).unwrap_err();
    assert_eq!(fault.code, "store_target_exists");
    assert_eq!(fs::read(sentinel).unwrap(), b"preserve");
}

#[test]
fn noncanonical_and_digest_tampered_ledgers_fail_before_target_creation() {
    let root = TempDirectory::new("invalid");
    let initial = ledger();
    let pretty = serde_json::to_vec_pretty(&initial).unwrap();
    let pretty_file = write_ledger(&root.0, &pretty);
    let pretty_config = config(&root, pretty_file, "pretty-store");
    let pretty_fault = bootstrap_identity_accounting_store(pretty_config.clone()).unwrap_err();
    assert_eq!(pretty_fault.code, "noncanonical_ledger_bytes");
    assert!(!pretty_config.store.directory.exists());

    let mut tampered = serde_json::to_value(&initial).unwrap();
    tampered["generation"] = serde_json::json!(2);
    let tampered_file = root.0.join("tampered.json");
    fs::write(&tampered_file, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let tampered_config = config(&root, tampered_file, "tampered-store");
    let tampered_fault = bootstrap_identity_accounting_store(tampered_config.clone()).unwrap_err();
    assert_eq!(tampered_fault.code, "invalid_identity_ledger");
    assert!(!tampered_config.store.directory.exists());
}

#[test]
fn snapshot_capacity_failure_removes_only_the_new_empty_target() {
    let root = TempDirectory::new("capacity");
    let input = write_ledger(&root.0, &serde_json::to_vec(&ledger()).unwrap());
    let mut bootstrap = config(&root, input, "store");
    bootstrap.store.maximum_snapshot_bytes = 1;

    let fault = bootstrap_identity_accounting_store(bootstrap.clone()).unwrap_err();
    assert_eq!(fault.code, "snapshot_byte_limit_exceeded");
    assert!(!bootstrap.store.directory.exists());
    assert!(bootstrap.ledger_file.is_file());
}

#[test]
fn invalid_and_oversized_ledger_bounds_fail_before_target_creation() {
    let root = TempDirectory::new("ledger-bounds");
    let bytes = serde_json::to_vec(&ledger()).unwrap();
    let input = write_ledger(&root.0, &bytes);

    let mut zero = config(&root, input.clone(), "zero-store");
    zero.maximum_ledger_bytes = 0;
    let zero_fault = bootstrap_identity_accounting_store(zero.clone()).unwrap_err();
    assert_eq!(zero_fault.code, "invalid_bootstrap_bound");
    assert!(!zero.store.directory.exists());

    let mut undersized = config(&root, input, "undersized-store");
    undersized.maximum_ledger_bytes = bytes.len() as u64 - 1;
    let undersized_fault = bootstrap_identity_accounting_store(undersized.clone()).unwrap_err();
    assert_eq!(undersized_fault.code, "ledger_byte_limit_exceeded");
    assert!(!undersized.store.directory.exists());
}

#[test]
fn one_shot_binary_emits_one_receipt_and_refuses_a_second_initialization() {
    let root = TempDirectory::new("subprocess");
    let initial = ledger();
    let input = write_ledger(&root.0, &serde_json::to_vec(&initial).unwrap());
    let store = root.absent_child("store");
    let binary = env!("CARGO_BIN_EXE_cantor-identity-accounting-bootstrap");
    let arguments = [
        "--store-dir",
        store.to_str().unwrap(),
        "--ledger-file",
        input.to_str().unwrap(),
        "--journal-id",
        "journal:bootstrap-fixture",
        "--max-ledger-bytes",
        "1048576",
        "--max-snapshot-bytes",
        "1048576",
        "--max-snapshots",
        "32",
    ];

    let first = Command::new(binary).args(arguments).output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        first.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let receipt: BootstrapReceipt = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(receipt.profile, BOOTSTRAP_RECEIPT_PROFILE);
    assert!(store.join(receipt.snapshot_filename).is_file());

    let second = Command::new(binary).args(arguments).output().unwrap();
    assert_eq!(second.status.code(), Some(2));
    assert!(second.stdout.is_empty());
    assert_eq!(fs::read_dir(store).unwrap().count(), 1);
}
