use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    ACCOUNTABLE_OBJECT_PROFILE, ACCOUNTING_HOST_REQUEST_PROFILE, AccountableObject,
    AccountableObjectPatch, AccountingHostOperation, AccountingHostRequest, AccountingHostResult,
    ContentDigest, IdentityLedger, SemanticId, finalize_accountable_object, new_accounting_journal,
    new_identity_ledger,
};
use cantor_identity_accounting_mcp::{
    AccountingMcpStatus, IdentityAccountingMcpResponse, IdentityAccountingMcpServer,
    SERVER_INSTRUCTIONS, SnapshotStore, SnapshotStoreConfig, TOOL_NAME,
};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

static TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cantor-accounting-{label}-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("unique fixture directory");
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture semantic identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn object(id: &str, state: &str) -> AccountableObject {
    finalize_accountable_object(AccountableObject {
        profile: ACCOUNTABLE_OBJECT_PROFILE.to_owned(),
        handle: sid(&format!("object:aircraft/{id}")),
        object_type: sid("aircraft"),
        labels: BTreeSet::from([format!("aircraft-{id}")]),
        differentiators: BTreeMap::from([("tail".to_owned(), id.to_owned())]),
        state: BTreeMap::from([("readiness".to_owned(), state.to_owned())]),
        roles: BTreeSet::from([sid("role:transport")]),
        purposes: BTreeSet::from([sid("purpose:dispatch")]),
        obligations: BTreeSet::new(),
        provenance_refs: BTreeSet::from([sid("source:durable-mcp-fixture")]),
        version: 1,
        record_digest: empty_digest(),
    })
    .expect("valid object")
}

fn ledger() -> IdentityLedger {
    new_identity_ledger(
        sid("basket:durable-mcp"),
        vec![object("001", "ready"), object("002", "maintenance")],
    )
    .expect("valid ledger")
}

fn journal() -> cantor_core::AccountingJournal {
    new_accounting_journal(sid("journal:durable-mcp"), ledger()).expect("valid journal")
}

fn config(directory: &TempDirectory) -> SnapshotStoreConfig {
    SnapshotStoreConfig {
        directory: directory.0.clone(),
        journal_id: sid("journal:durable-mcp"),
        maximum_snapshot_bytes: 4 * 1024 * 1024,
        maximum_snapshots: 64,
    }
}

fn request(
    journal: &cantor_core::AccountingJournal,
    id: &str,
    operation: AccountingHostOperation,
) -> AccountingHostRequest {
    AccountingHostRequest {
        profile: ACCOUNTING_HOST_REQUEST_PROFILE.to_owned(),
        request_id: sid(id),
        expected_journal_digest: journal.journal_digest.clone(),
        operation,
    }
}

fn patch(journal: &cantor_core::AccountingJournal, readiness: &str) -> AccountableObjectPatch {
    let ledger = &journal.ledgers[&journal.head_ledger_digest.value];
    let handle = sid("object:aircraft/002");
    AccountableObjectPatch {
        expected_ledger_digest: ledger.ledger_digest.clone(),
        handle: handle.clone(),
        expected_version: ledger.objects[&handle].version,
        labels: None,
        differentiators: None,
        state: Some(BTreeMap::from([(
            "readiness".to_owned(),
            readiness.to_owned(),
        )])),
        roles: None,
        purposes: None,
        obligations: None,
        provenance_refs: None,
    }
}

fn arguments(request: AccountingHostRequest) -> serde_json::Map<String, Value> {
    json!({ "request": request })
        .as_object()
        .expect("arguments object")
        .clone()
}

fn structured(result: &rmcp::model::CallToolResult) -> IdentityAccountingMcpResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("structured result"),
    )
    .expect("typed MCP response")
}

#[test]
fn metadata_declares_one_closed_world_durable_accounting_tool() {
    let tool = IdentityAccountingMcpServer::tool_definition();
    assert_eq!(tool.name, TOOL_NAME);
    assert!(tool.output_schema.is_some());
    let annotations = tool.annotations.expect("annotations");
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert_eq!(
        tool.input_schema.get("additionalProperties"),
        Some(&json!(false))
    );
    let schema = serde_json::to_string(&tool.input_schema).unwrap();
    for operation in [
        "inspect_journal",
        "project",
        "resolve",
        "inspect_object",
        "read_ledger",
        "read_event",
        "apply_patch",
        "admit_object",
    ] {
        assert!(schema.contains(operation), "missing {operation}");
    }
    assert!(SERVER_INSTRUCTIONS.contains("persists"));
}

#[tokio::test(flavor = "current_thread")]
async fn mutation_persists_before_publish_and_restart_restores_exact_history() {
    let directory = TempDirectory::new("restart");
    let initial = journal();
    SnapshotStore::initialize(config(&directory), &initial).expect("initialize store");
    let server = IdentityAccountingMcpServer::open(config(&directory)).expect("open server");

    let applied = server
        .execute_tool_arguments(Some(arguments(request(
            &initial,
            "request:persist",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(patch(&initial, "ready")),
            },
        ))))
        .await;
    assert_eq!(structured(&applied).status, AccountingMcpStatus::Succeeded);
    let advanced = server.snapshot().await;
    assert_eq!(advanced.events.len(), 2);
    assert_eq!(
        fs::read_dir(&directory.0).unwrap().count(),
        2,
        "one immutable file per generation"
    );

    let restarted = IdentityAccountingMcpServer::open(config(&directory)).expect("restart");
    assert_eq!(restarted.snapshot().await, advanced);
    let old_event = advanced.events[0].event_id.clone();
    let read = restarted
        .execute_tool_arguments(Some(arguments(request(
            &advanced,
            "request:read-after-restart",
            AccountingHostOperation::ReadEvent {
                event_id: old_event.clone(),
            },
        ))))
        .await;
    let result = structured(&read).result.expect("read result").result;
    let AccountingHostResult::Event { event } = result else {
        panic!("expected event")
    };
    assert_eq!(event.event_id, old_event);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_equal_root_mutations_yield_one_persisted_successor_and_one_refusal() {
    let directory = TempDirectory::new("concurrency");
    let initial = journal();
    SnapshotStore::initialize(config(&directory), &initial).unwrap();
    let server = IdentityAccountingMcpServer::open(config(&directory)).unwrap();
    let command = request(
        &initial,
        "request:concurrent",
        AccountingHostOperation::ApplyPatch {
            patch: Box::new(patch(&initial, "ready")),
        },
    );
    let left = server.clone();
    let right = server.clone();
    let (first, second) = tokio::join!(
        left.execute_tool_arguments(Some(arguments(command.clone()))),
        right.execute_tool_arguments(Some(arguments(command)))
    );
    let statuses = [structured(&first).status, structured(&second).status];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == AccountingMcpStatus::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == AccountingMcpStatus::Refused)
            .count(),
        1
    );
    assert_eq!(server.snapshot().await.events.len(), 2);
    assert_eq!(
        SnapshotStore::new(config(&directory))
            .unwrap()
            .load()
            .unwrap()
            .events
            .len(),
        2
    );
}

#[test]
fn recovery_refuses_forks_name_mismatch_and_entry_overflow() {
    let fork_directory = TempDirectory::new("fork");
    let initial = journal();
    let store = SnapshotStore::initialize(config(&fork_directory), &initial).unwrap();
    let left = cantor_core::execute_accounting_host_request(
        &initial,
        request(
            &initial,
            "request:left",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(patch(&initial, "ready")),
            },
        ),
    )
    .unwrap()
    .successor
    .unwrap();
    let right = cantor_core::execute_accounting_host_request(
        &initial,
        request(
            &initial,
            "request:right",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(patch(&initial, "grounded")),
            },
        ),
    )
    .unwrap()
    .successor
    .unwrap();
    store.persist(&left).unwrap();
    store.persist(&right).unwrap();
    assert_eq!(store.load().unwrap_err().code, "journal_fork");

    let mismatch_directory = TempDirectory::new("name-mismatch");
    let bytes = cantor_core::encode_accounting_journal(&initial).unwrap();
    fs::write(
        mismatch_directory
            .0
            .join(format!("{}.json", "0".repeat(64))),
        bytes,
    )
    .unwrap();
    assert_eq!(
        SnapshotStore::new(config(&mismatch_directory))
            .unwrap()
            .load()
            .unwrap_err()
            .code,
        "snapshot_name_mismatch"
    );

    let overflow_directory = TempDirectory::new("overflow");
    SnapshotStore::initialize(config(&overflow_directory), &initial).unwrap();
    fs::write(overflow_directory.0.join("unrelated"), b"x").unwrap();
    let mut bounded = config(&overflow_directory);
    bounded.maximum_snapshots = 1;
    assert_eq!(
        SnapshotStore::new(bounded)
            .unwrap()
            .load()
            .unwrap_err()
            .code,
        "store_entry_limit_exceeded"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn official_stdio_client_inspects_persisted_journal() {
    let directory = TempDirectory::new("official");
    let initial = journal();
    SnapshotStore::initialize(config(&directory), &initial).unwrap();
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-identity-accounting-mcp"))
            .configure(|command| {
                command
                    .arg("--store-dir")
                    .arg(&directory.0)
                    .arg("--journal-id")
                    .arg("journal:durable-mcp")
                    .arg("--max-snapshot-bytes")
                    .arg((4 * 1024 * 1024).to_string())
                    .arg("--max-snapshots")
                    .arg("64");
            }),
    )
    .expect("subprocess starts");
    let client = ().serve(transport).await.expect("MCP initializes");
    let tools = client.list_all_tools().await.expect("tools list");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);
    let result = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments(request(
                &initial,
                "request:official-summary",
                AccountingHostOperation::InspectJournal,
            ))),
        )
        .await
        .expect("tool call");
    let response: IdentityAccountingMcpResponse =
        serde_json::from_value(result.structured_content.expect("structured content")).unwrap();
    assert_eq!(response.status, AccountingMcpStatus::Succeeded);
    let AccountingHostResult::JournalSummary { event_count, .. } =
        response.result.expect("summary").result
    else {
        panic!("expected summary")
    };
    assert_eq!(event_count, 1);
    client.cancel().await.expect("client closes");
}

#[tokio::test(flavor = "current_thread")]
async fn persistence_failure_and_invalid_arguments_leave_the_head_unchanged() {
    let directory = TempDirectory::new("persist-failure");
    let initial = journal();
    SnapshotStore::initialize(config(&directory), &initial).unwrap();
    let initial_bytes = cantor_core::encode_accounting_journal(&initial).unwrap();
    let mut constrained = config(&directory);
    constrained.maximum_snapshot_bytes = initial_bytes.len() as u64 + 128;
    let server = IdentityAccountingMcpServer::open(constrained).unwrap();

    let mut oversized_patch = patch(&initial, "ready");
    oversized_patch.state = Some(BTreeMap::from([(
        "readiness".to_owned(),
        "x".repeat(8 * 1024),
    )]));
    let refused = server
        .execute_tool_arguments(Some(arguments(request(
            &initial,
            "request:oversized-successor",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(oversized_patch),
            },
        ))))
        .await;
    assert_eq!(structured(&refused).status, AccountingMcpStatus::StoreFault);
    assert_eq!(server.snapshot().await, initial);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);

    let full_directory = TempDirectory::new("full-store");
    SnapshotStore::initialize(config(&full_directory), &initial).unwrap();
    let mut full_config = config(&full_directory);
    full_config.maximum_snapshots = 1;
    let full_server = IdentityAccountingMcpServer::open(full_config).unwrap();
    let full = full_server
        .execute_tool_arguments(Some(arguments(request(
            &initial,
            "request:full-store",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(patch(&initial, "ready")),
            },
        ))))
        .await;
    assert_eq!(structured(&full).status, AccountingMcpStatus::StoreFault);
    assert_eq!(full_server.snapshot().await, initial);

    let invalid = server
        .execute_tool_arguments(Some(
            json!({"request": request(&initial, "request:invalid", AccountingHostOperation::InspectJournal), "invented": true})
                .as_object()
                .unwrap()
                .clone(),
        ))
        .await;
    assert_eq!(
        structured(&invalid).status,
        AccountingMcpStatus::InvalidRequest
    );
    assert_eq!(server.snapshot().await, initial);
}
