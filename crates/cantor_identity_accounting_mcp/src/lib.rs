//! Durable local MCP custody for Cantor identity-accounting journals.

#![recursion_limit = "512"]

use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use cantor_core::{
    AccountingHostRequest, AccountingHostResponse, AccountingJournal, IdentityLedger, SemanticId,
    SharedAttentionToolFault, decode_accounting_journal, encode_accounting_journal,
    execute_accounting_host_request, new_accounting_journal, validate_accounting_journal,
    validate_identity_ledger,
};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestMethod, CallToolRequestParams, CallToolResponse, CallToolResult,
        ContentBlock, Implementation, JsonObject, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
    },
    service::{RequestContext, RoleServer},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

pub const TOOL_NAME: &str = "attend_accountable_objects";
pub const ADAPTER_PROFILE: &str = "cantor-identity-accounting-durable-mcp/0.1";
pub const BOOTSTRAP_RECEIPT_PROFILE: &str = "cantor-identity-accounting-store-bootstrap/0.1";
pub const MAX_ARGUMENT_BYTES: usize = 32 * 1024 * 1024;
pub const SERVER_INSTRUCTIONS: &str = "Use attend_accountable_objects to inspect, project, resolve, read, or compare-and-set one exact accountable-object journal. Carry the current journal digest on every request. Read operations are inert; apply_patch persists a complete canonical successor before it becomes visible. Preserve ambiguous and unknown resolutions. This local stdio server invokes no model, opens no network listener, signs no meaning, and authorizes no effect beyond declared process-restart snapshot custody.";

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct SnapshotStoreConfig {
    pub directory: PathBuf,
    pub journal_id: SemanticId,
    pub maximum_snapshot_bytes: u64,
    pub maximum_snapshots: usize,
}

#[derive(Clone, Debug)]
pub struct SnapshotStore {
    config: SnapshotStoreConfig,
}

#[derive(Clone, Debug)]
pub struct BootstrapStoreConfig {
    pub store: SnapshotStoreConfig,
    pub ledger_file: PathBuf,
    pub maximum_ledger_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootstrapReceipt {
    pub profile: String,
    pub journal_id: SemanticId,
    pub journal_digest: cantor_core::ContentDigest,
    pub basket_id: SemanticId,
    pub head_ledger_digest: cantor_core::ContentDigest,
    pub genesis_event_id: SemanticId,
    pub snapshot_filename: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreFault {
    pub code: &'static str,
    pub message: String,
}

impl StoreFault {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: bounded(&message.into()),
        }
    }
}

impl fmt::Display for StoreFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for StoreFault {}

#[derive(Clone, Debug)]
pub struct IdentityAccountingMcpServer {
    store: SnapshotStore,
    journal: Arc<Mutex<AccountingJournal>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttendAccountableObjectsArguments {
    pub request: AccountingHostRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccountingMcpStatus {
    Succeeded,
    Refused,
    InvalidRequest,
    StoreFault,
    InternalFault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAccountingMcpResponse {
    pub profile: String,
    pub status: AccountingMcpStatus,
    pub result: Option<AccountingHostResponse>,
    pub fault: Option<SharedAttentionToolFault>,
    pub nonclaims: Vec<String>,
}

impl IdentityAccountingMcpResponse {
    fn success(result: AccountingHostResponse) -> Self {
        Self::new(AccountingMcpStatus::Succeeded, Some(result), None)
    }

    fn fault(status: AccountingMcpStatus, code: &str, message: impl Into<String>) -> Self {
        Self::new(
            status,
            None,
            Some(SharedAttentionToolFault {
                code: code.to_owned(),
                message: bounded(&message.into()),
                subject_refs: Default::default(),
            }),
        )
    }

    fn new(
        status: AccountingMcpStatus,
        result: Option<AccountingHostResponse>,
        fault: Option<SharedAttentionToolFault>,
    ) -> Self {
        Self {
            profile: ADAPTER_PROFILE.to_owned(),
            status,
            result,
            fault,
            nonclaims: vec![
                "snapshot custody does not prove external truth or sign meaning".to_owned(),
                "directory protection retention backup and access policy remain operator duties"
                    .to_owned(),
                "file sync and immutable rename support process restart but do not prove survival of hardware or volume failure".to_owned(),
                "no model hidden state network listener or external effect is accessed".to_owned(),
            ],
        }
    }

    const fn is_error(&self) -> bool {
        !matches!(self.status, AccountingMcpStatus::Succeeded)
    }
}

impl SnapshotStore {
    pub fn new(config: SnapshotStoreConfig) -> Result<Self, StoreFault> {
        if config.maximum_snapshot_bytes == 0 || config.maximum_snapshots == 0 {
            return Err(StoreFault::new(
                "invalid_store_bound",
                "snapshot byte and entry bounds must be positive",
            ));
        }
        let metadata = fs::symlink_metadata(&config.directory)
            .map_err(|error| io_fault("store_directory_unavailable", error))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(StoreFault::new(
                "invalid_store_directory",
                "store path must be an existing non-symlink directory",
            ));
        }
        Ok(Self { config })
    }

    pub fn initialize(
        config: SnapshotStoreConfig,
        journal: &AccountingJournal,
    ) -> Result<Self, StoreFault> {
        let store = Self::new(config)?;
        if journal.journal_id != store.config.journal_id {
            return Err(StoreFault::new(
                "journal_identity_mismatch",
                "initial journal identity differs from store configuration",
            ));
        }
        store.persist(journal)?;
        Ok(store)
    }

    pub fn load(&self) -> Result<AccountingJournal, StoreFault> {
        let mut candidates = BTreeMap::<String, AccountingJournal>::new();
        let mut scanned = 0usize;
        for entry in fs::read_dir(&self.config.directory)
            .map_err(|error| io_fault("store_scan_failed", error))?
        {
            scanned = scanned.checked_add(1).ok_or_else(|| {
                StoreFault::new("store_entry_overflow", "store entry count overflowed")
            })?;
            if scanned > self.config.maximum_snapshots {
                return Err(StoreFault::new(
                    "store_entry_limit_exceeded",
                    "store directory exceeds its bounded entry count",
                ));
            }
            let entry = entry.map_err(|error| io_fault("store_entry_failed", error))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(expected_digest) = snapshot_name_digest(&name) else {
                continue;
            };
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| io_fault("snapshot_metadata_failed", error))?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(StoreFault::new(
                    "invalid_snapshot_type",
                    format!("snapshot {name} is not a regular non-symlink file"),
                ));
            }
            if metadata.len() > self.config.maximum_snapshot_bytes {
                return Err(StoreFault::new(
                    "snapshot_byte_limit_exceeded",
                    format!("snapshot {name} exceeds its byte bound"),
                ));
            }
            let bytes =
                fs::read(entry.path()).map_err(|error| io_fault("snapshot_read_failed", error))?;
            if bytes.len() as u64 > self.config.maximum_snapshot_bytes {
                return Err(StoreFault::new(
                    "snapshot_byte_limit_exceeded",
                    format!("snapshot {name} grew beyond its byte bound"),
                ));
            }
            let journal = decode_accounting_journal(&bytes, self.config.maximum_snapshot_bytes)
                .map_err(|error| StoreFault::new("invalid_snapshot", error.to_string()))?;
            if journal.journal_id != self.config.journal_id {
                continue;
            }
            if journal.journal_digest.value != expected_digest {
                return Err(StoreFault::new(
                    "snapshot_name_mismatch",
                    format!("snapshot {name} differs from its journal digest"),
                ));
            }
            candidates.insert(expected_digest, journal);
        }
        if candidates.is_empty() {
            return Err(StoreFault::new(
                "journal_snapshot_absent",
                "no canonical snapshot exists for the requested journal identity",
            ));
        }
        let maximal_length = candidates
            .values()
            .map(|journal| journal.events.len())
            .max()
            .expect("nonempty candidates");
        let maxima = candidates
            .values()
            .filter(|journal| journal.events.len() == maximal_length)
            .collect::<Vec<_>>();
        if maxima.len() != 1 {
            return Err(StoreFault::new(
                "journal_fork",
                "store contains more than one maximal journal history",
            ));
        }
        let selected = maxima[0];
        for candidate in candidates.values() {
            if !is_exact_prefix(candidate, selected) {
                return Err(StoreFault::new(
                    "journal_fork",
                    "store contains an incomparable journal history",
                ));
            }
        }
        Ok(selected.clone())
    }

    pub fn persist(&self, journal: &AccountingJournal) -> Result<PathBuf, StoreFault> {
        validate_accounting_journal(journal)
            .map_err(|error| StoreFault::new("invalid_journal", error.to_string()))?;
        if journal.journal_id != self.config.journal_id {
            return Err(StoreFault::new(
                "journal_identity_mismatch",
                "candidate journal identity differs from store configuration",
            ));
        }
        let bytes = encode_accounting_journal(journal)
            .map_err(|error| StoreFault::new("journal_encoding_failed", error.to_string()))?;
        if bytes.len() as u64 > self.config.maximum_snapshot_bytes {
            return Err(StoreFault::new(
                "snapshot_byte_limit_exceeded",
                "candidate journal exceeds its snapshot byte bound",
            ));
        }
        let target = self
            .config
            .directory
            .join(format!("{}.json", journal.journal_digest.value));
        if target.exists() {
            return verify_existing(&target, &bytes).map(|()| target);
        }
        let entry_count = fs::read_dir(&self.config.directory)
            .map_err(|error| io_fault("store_scan_failed", error))?
            .try_fold(0usize, |count, entry| {
                entry.map_err(|error| io_fault("store_entry_failed", error))?;
                count.checked_add(1).ok_or_else(|| {
                    StoreFault::new("store_entry_overflow", "store entry count overflowed")
                })
            })?;
        if entry_count >= self.config.maximum_snapshots {
            return Err(StoreFault::new(
                "store_entry_limit_exceeded",
                "store directory has no remaining bounded snapshot capacity",
            ));
        }
        let temporary = self.config.directory.join(format!(
            ".partial-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let write_result = (|| -> Result<(), StoreFault> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| io_fault("snapshot_create_failed", error))?;
            file.write_all(&bytes)
                .map_err(|error| io_fault("snapshot_write_failed", error))?;
            file.sync_all()
                .map_err(|error| io_fault("snapshot_sync_failed", error))?;
            if let Err(error) = fs::rename(&temporary, &target) {
                if target.exists() {
                    verify_existing(&target, &bytes)?;
                    fs::remove_file(&temporary)
                        .map_err(|cleanup| io_fault("snapshot_cleanup_failed", cleanup))?;
                } else {
                    return Err(io_fault("snapshot_publish_failed", error));
                }
            }
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result?;
        verify_existing(&target, &bytes)?;
        Ok(target)
    }
}

pub fn bootstrap_identity_accounting_store(
    config: BootstrapStoreConfig,
) -> Result<BootstrapReceipt, StoreFault> {
    if config.maximum_ledger_bytes == 0
        || config.store.maximum_snapshot_bytes == 0
        || config.store.maximum_snapshots == 0
    {
        return Err(StoreFault::new(
            "invalid_bootstrap_bound",
            "ledger byte, snapshot byte, and snapshot count bounds must be positive",
        ));
    }
    let metadata = fs::symlink_metadata(&config.ledger_file)
        .map_err(|error| io_fault("ledger_file_unavailable", error))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreFault::new(
            "invalid_ledger_file",
            "ledger input must be an existing regular non-symlink file",
        ));
    }
    if metadata.len() > config.maximum_ledger_bytes {
        return Err(StoreFault::new(
            "ledger_byte_limit_exceeded",
            "ledger input metadata exceeds its byte bound",
        ));
    }
    let ledger_bytes =
        fs::read(&config.ledger_file).map_err(|error| io_fault("ledger_read_failed", error))?;
    if ledger_bytes.len() as u64 > config.maximum_ledger_bytes {
        return Err(StoreFault::new(
            "ledger_byte_limit_exceeded",
            "ledger input grew beyond its byte bound",
        ));
    }
    let ledger: IdentityLedger = serde_json::from_slice(&ledger_bytes).map_err(|error| {
        StoreFault::new(
            "invalid_ledger_machine_form",
            format!("ledger machine form is invalid: {error}"),
        )
    })?;
    validate_identity_ledger(&ledger)
        .map_err(|error| StoreFault::new("invalid_identity_ledger", error.to_string()))?;
    let canonical_ledger = serde_json::to_vec(&ledger).map_err(|error| {
        StoreFault::new(
            "ledger_encoding_failed",
            format!("ledger canonical replay failed: {error}"),
        )
    })?;
    if canonical_ledger != ledger_bytes {
        return Err(StoreFault::new(
            "noncanonical_ledger_bytes",
            "ledger input is valid JSON but not canonical bytes",
        ));
    }
    let journal = new_accounting_journal(config.store.journal_id.clone(), ledger)
        .map_err(|error| StoreFault::new("genesis_failed", error.to_string()))?;

    match fs::symlink_metadata(&config.store.directory) {
        Ok(_) => {
            return Err(StoreFault::new(
                "store_target_exists",
                "bootstrap store path already exists",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_fault("store_target_inspection_failed", error)),
    }
    fs::create_dir(&config.store.directory)
        .map_err(|error| io_fault("store_directory_create_failed", error))?;

    let transaction = (|| -> Result<BootstrapReceipt, StoreFault> {
        let store = SnapshotStore::initialize(config.store.clone(), &journal)?;
        let restored = store.load()?;
        if restored != journal {
            return Err(StoreFault::new(
                "bootstrap_reload_mismatch",
                "reloaded genesis journal differs from the persisted candidate",
            ));
        }
        let genesis = restored
            .events
            .first()
            .ok_or_else(|| StoreFault::new("genesis_event_absent", "genesis event is absent"))?;
        Ok(BootstrapReceipt {
            profile: BOOTSTRAP_RECEIPT_PROFILE.to_owned(),
            journal_id: restored.journal_id.clone(),
            journal_digest: restored.journal_digest.clone(),
            basket_id: restored.basket_id.clone(),
            head_ledger_digest: restored.head_ledger_digest.clone(),
            genesis_event_id: genesis.event_id.clone(),
            snapshot_filename: format!("{}.json", restored.journal_digest.value),
        })
    })();
    match transaction {
        Ok(receipt) => Ok(receipt),
        Err(fault) => match fs::remove_dir(&config.store.directory) {
            Ok(()) => Err(fault),
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => Err(fault),
            Err(error) => Err(StoreFault::new(
                "bootstrap_cleanup_failed",
                format!("{}; exact empty-directory cleanup failed: {error}", fault),
            )),
        },
    }
}

impl IdentityAccountingMcpServer {
    pub fn open(config: SnapshotStoreConfig) -> Result<Self, StoreFault> {
        let store = SnapshotStore::new(config)?;
        let journal = store.load()?;
        Ok(Self {
            store,
            journal: Arc::new(Mutex::new(journal)),
        })
    }

    pub fn tool_definition() -> Tool {
        Tool::new(
            TOOL_NAME,
            "Inspect, project, resolve, read, or compare-and-set one durable accountable-object journal. Mutations are persisted as complete replayable snapshots before becoming visible; ambiguous identity remains explicit.",
            schema_object::<AttendAccountableObjectsArguments>(),
        )
        .with_title("Attend accountable objects")
        .with_raw_output_schema(Arc::new(schema_object::<IdentityAccountingMcpResponse>()))
        .with_annotations(
            ToolAnnotations::with_title("Attend accountable objects")
                .read_only(false)
                .destructive(false)
                .idempotent(false)
                .open_world(false),
        )
    }

    pub async fn snapshot(&self) -> AccountingJournal {
        self.journal.lock().await.clone()
    }

    pub async fn execute_tool_arguments(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let value = Value::Object(arguments.unwrap_or_default());
        let encoded_length = match serde_json::to_vec(&value) {
            Ok(encoded) => encoded.len(),
            Err(error) => {
                return response_result(IdentityAccountingMcpResponse::fault(
                    AccountingMcpStatus::InvalidRequest,
                    "invalid_arguments",
                    error.to_string(),
                ));
            }
        };
        if encoded_length > MAX_ARGUMENT_BYTES {
            return response_result(IdentityAccountingMcpResponse::fault(
                AccountingMcpStatus::InvalidRequest,
                "argument_limit_exceeded",
                format!("tool arguments contain {encoded_length} bytes"),
            ));
        }
        let parsed: AttendAccountableObjectsArguments = match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return response_result(IdentityAccountingMcpResponse::fault(
                    AccountingMcpStatus::InvalidRequest,
                    "invalid_arguments",
                    error.to_string(),
                ));
            }
        };
        let mut journal = self.journal.lock().await;
        match execute_accounting_host_request(&journal, parsed.request) {
            Ok(transition) => {
                if let Some(successor) = transition.successor {
                    if let Err(error) = self.store.persist(&successor) {
                        return response_result(IdentityAccountingMcpResponse::fault(
                            AccountingMcpStatus::StoreFault,
                            error.code,
                            error.message,
                        ));
                    }
                    *journal = successor;
                }
                response_result(IdentityAccountingMcpResponse::success(transition.response))
            }
            Err(error) => response_result(IdentityAccountingMcpResponse::new(
                AccountingMcpStatus::Refused,
                None,
                Some(error.into()),
            )),
        }
    }
}

impl ServerHandler for IdentityAccountingMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("cantor-identity-accounting", env!("CARGO_PKG_VERSION"))
                    .with_title("Cantor durable identity accounting")
                    .with_description("Replayable local accountable-object custody over stdio."),
            )
            .with_instructions(SERVER_INSTRUCTIONS)
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        (name == TOOL_NAME).then(Self::tool_definition)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![
            Self::tool_definition(),
        ]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if request.name != TOOL_NAME {
            return Err(McpError::method_not_found::<CallToolRequestMethod>());
        }
        Ok(self.execute_tool_arguments(request.arguments).await.into())
    }
}

fn is_exact_prefix(ancestor: &AccountingJournal, descendant: &AccountingJournal) -> bool {
    ancestor.journal_id == descendant.journal_id
        && ancestor.basket_id == descendant.basket_id
        && ancestor.events.len() <= descendant.events.len()
        && ancestor.events == descendant.events[..ancestor.events.len()]
        && ancestor
            .ledgers
            .iter()
            .all(|(key, ledger)| descendant.ledgers.get(key) == Some(ledger))
}

fn snapshot_name_digest(name: &str) -> Option<String> {
    let digest = name.strip_suffix(".json")?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| digest.to_owned())
}

fn verify_existing(path: &Path, expected: &[u8]) -> Result<(), StoreFault> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_fault("snapshot_metadata_failed", error))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreFault::new(
            "invalid_snapshot_type",
            "content-addressed snapshot target is not a regular non-symlink file",
        ));
    }
    let observed = fs::read(path).map_err(|error| io_fault("snapshot_read_failed", error))?;
    if observed != expected {
        return Err(StoreFault::new(
            "snapshot_digest_collision",
            "existing content-addressed snapshot has different bytes",
        ));
    }
    Ok(())
}

fn response_result(response: IdentityAccountingMcpResponse) -> CallToolResult {
    let (value, is_error) = match serde_json::to_value(&response) {
        Ok(value) => (value, response.is_error()),
        Err(error) => (
            json!({
                "profile": ADAPTER_PROFILE,
                "status": "internal_fault",
                "result": null,
                "fault": {"code": "response_encoding_failed", "message": bounded(&error.to_string()), "subject_refs": []},
                "nonclaims": []
            }),
            true,
        ),
    };
    let status = value["status"].as_str().unwrap_or("internal_fault");
    let content = vec![ContentBlock::text(format!(
        "Cantor identity accounting returned {status}; use structuredContent as the complete result."
    ))];
    let mut result = if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = Some(value);
    result
}

fn io_fault(code: &'static str, error: io::Error) -> StoreFault {
    StoreFault::new(code, error.to_string())
}

fn bounded(message: &str) -> String {
    message.chars().take(512).collect()
}

fn schema_object<T: JsonSchema>() -> JsonObject {
    serde_json::to_value(schemars::schema_for!(T))
        .expect("generated schema serializes")
        .as_object()
        .expect("generated schema root is an object")
        .clone()
}
