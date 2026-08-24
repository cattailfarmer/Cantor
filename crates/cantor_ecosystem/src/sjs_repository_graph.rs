//! Pure verification of a supplied SJS repository change set against an
//! independently supplied diff inventory.
//!
//! This module never invokes Git or touches a workspace. A successful receipt
//! proves only that two bounded machine forms agree and satisfy the governed
//! graph, element-history, and coverage contract.

use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const CHANGE_SET_PROFILE: &str = "cantor-sjs-repository-change-set/0.1";
pub const DIFF_INVENTORY_PROFILE: &str = "cantor-sjs-diff-inventory/0.1";
pub const ELEMENT_EVENT_PROFILE: &str = "cantor-sjs-element-history-event/0.1";
pub const VERIFICATION_RECEIPT_PROFILE: &str = "cantor-sjs-repository-graph-verification/0.1";

pub const MAX_CHANGE_SET_BYTES: usize = 1_048_576;
pub const MAX_DIFF_INVENTORY_BYTES: usize = 524_288;
pub const MAX_RECEIPT_BYTES: usize = 65_536;

const MAX_DIFF_ENTRIES: usize = 1_024;
const MAX_NODES: usize = 1_024;
const MAX_EDGES: usize = 4_096;
const MAX_EVENTS: usize = 1_024;
const MAX_FOREIGN_EXCLUSIONS: usize = 1_024;
const MAX_EVENT_REFS: usize = 128;
const MAX_EVENT_CHANGES: usize = 128;
const MAX_TEXT_ITEMS: usize = 128;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_SEMANTIC_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 4_096;

const INVENTORY_DOMAIN: &[u8] = b"cantor:sjs-repository-graph:diff-inventory:0.1";
const EVENT_DOMAIN: &[u8] = b"cantor:sjs-repository-graph:element-event:0.1";
const CHANGE_SET_DOMAIN: &[u8] = b"cantor:sjs-repository-graph:change-set:0.1";
const RECEIPT_DOMAIN: &[u8] = b"cantor:sjs-repository-graph:receipt:0.1";
const NONAUTHORITY: &str = "verification proves supplied graph and inventory agreement only; it grants no Git observation mutation staging commit push publication trust provider activation or self-signature authority";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    GeneratedRefresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElementOperation {
    Add,
    Modify,
    Correct,
    Rename,
    Move,
    Supersede,
    Invalidate,
    Delete,
    Restore,
    GeneratedRefresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeKind {
    Source,
    Specification,
    Requirement,
    Constraint,
    Justification,
    Plan,
    Element,
    ElementHistoryEvent,
    ImplementationArtifact,
    Test,
    Evidence,
    Proof,
    Solution,
    NarrativeTurn,
    OperationalFault,
    Signature,
    Frontier,
    ChangeSet,
    CommitBookend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphEdgeKind {
    DerivedFrom,
    RequiredBy,
    ConstrainedBy,
    JustifiedBy,
    PlannedBy,
    Modifies,
    Implements,
    GeneratedFrom,
    VerifiedBy,
    ProvenBy,
    RecordedIn,
    Supersedes,
    Invalidates,
    Corrects,
    RollsBack,
    UnresolvedAs,
    BookendedBy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    Candidate,
    Committed,
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationAuthority {
    VerificationOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffCoordinate {
    pub status: DiffStatus,
    pub old_path: Option<String>,
    pub new_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffEntry {
    pub status: DiffStatus,
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
}

impl DiffEntry {
    fn coordinate(&self) -> DiffCoordinate {
        DiffCoordinate {
            status: self.status,
            old_path: self.old_path.clone(),
            new_path: self.new_path.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffInventory {
    pub profile: String,
    pub repository_id: String,
    pub branch_ref: String,
    pub predecessor_commit: String,
    pub entries: Vec<DiffEntry>,
    pub inventory_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    pub node_id: String,
    pub kind: GraphNodeKind,
    pub repository_path: Option<String>,
    pub content_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    pub edge_id: String,
    pub kind: GraphEdgeKind,
    pub source_node_id: String,
    pub target_node_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementHistoryEvent {
    pub profile: String,
    pub event_uuid: String,
    pub event_node_id: String,
    pub element_id: String,
    pub element_node_id: String,
    pub operation: ElementOperation,
    pub turn_uuid: String,
    pub conversation_uuid: String,
    pub change_set_uuid: String,
    pub covered_changes: Vec<DiffCoordinate>,
    pub source_node_ids: Vec<String>,
    pub requirement_node_ids: Vec<String>,
    pub constraint_node_ids: Vec<String>,
    pub justification_node_ids: Vec<String>,
    pub plan_node_ids: Vec<String>,
    pub implementation_node_ids: Vec<String>,
    pub evidence_node_ids: Vec<String>,
    pub proof_node_ids: Vec<String>,
    pub narrative_node_ids: Vec<String>,
    pub frontier_node_ids: Vec<String>,
    pub reason_summary: String,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
    pub tombstone: bool,
    pub generated: bool,
    pub nonclaims: Vec<String>,
    pub unresolved_frontier: Vec<String>,
    pub event_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForeignExclusion {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetManifest {
    pub profile: String,
    pub change_set_uuid: String,
    pub repository_id: String,
    pub branch_ref: String,
    pub predecessor_commit: String,
    pub resulting_commit: Option<String>,
    pub publication_state: PublicationState,
    pub turn_uuid: String,
    pub conversation_uuid: String,
    pub inventory_sha256: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub events: Vec<ElementHistoryEvent>,
    pub foreign_exclusions: Vec<ForeignExclusion>,
    pub authority: VerificationAuthority,
    pub physical_contact: bool,
    pub change_set_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    pub profile: String,
    pub change_set_uuid: String,
    pub change_set_sha256: String,
    pub inventory_sha256: String,
    pub repository_id: String,
    pub diff_entry_count: u32,
    pub graph_node_count: u32,
    pub graph_edge_count: u32,
    pub element_event_count: u32,
    pub covered_change_count: u32,
    pub foreign_exclusion_count: u32,
    pub complete_coverage: bool,
    pub authority: VerificationAuthority,
    pub physical_contact: bool,
    pub nonauthority: String,
    pub result_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphFaultCode {
    Profile,
    Identity,
    Path,
    Inventory,
    Graph,
    Event,
    Coverage,
    Foreign,
    Digest,
    Authority,
    Serialization,
    Resource,
    Io,
    Cli,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphFault {
    pub code: GraphFaultCode,
    pub message: String,
}

impl fmt::Display for GraphFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for GraphFault {}

pub fn diff_inventory_digest(inventory: &DiffInventory) -> Result<String, GraphFault> {
    let mut body = inventory.clone();
    body.inventory_sha256.clear();
    digest_form(INVENTORY_DOMAIN, &body)
}

pub fn element_history_event_digest(event: &ElementHistoryEvent) -> Result<String, GraphFault> {
    let mut body = event.clone();
    body.event_sha256.clear();
    digest_form(EVENT_DOMAIN, &body)
}

pub fn change_set_manifest_digest(manifest: &ChangeSetManifest) -> Result<String, GraphFault> {
    let mut body = manifest.clone();
    body.change_set_sha256.clear();
    digest_form(CHANGE_SET_DOMAIN, &body)
}

pub fn verification_receipt_digest(receipt: &VerificationReceipt) -> Result<String, GraphFault> {
    let mut body = receipt.clone();
    body.result_sha256.clear();
    digest_form(RECEIPT_DOMAIN, &body)
}

pub fn validate_diff_inventory(inventory: &DiffInventory) -> Result<(), GraphFault> {
    if inventory.profile != DIFF_INVENTORY_PROFILE {
        return fault(GraphFaultCode::Profile, "diff inventory profile differs");
    }
    validate_encoded_bound(inventory, MAX_DIFF_INVENTORY_BYTES, "diff inventory")?;
    validate_semantic_id(&inventory.repository_id, "repository_id")?;
    validate_branch_ref(&inventory.branch_ref)?;
    validate_commit(&inventory.predecessor_commit, "predecessor_commit")?;
    if inventory.entries.is_empty() || inventory.entries.len() > MAX_DIFF_ENTRIES {
        return fault(
            GraphFaultCode::Resource,
            "diff entry count is empty or over bound",
        );
    }
    let mut coordinates = HashSet::new();
    for entry in &inventory.entries {
        validate_diff_entry(entry)?;
        if !coordinates.insert(entry.coordinate()) {
            return fault(GraphFaultCode::Inventory, "duplicate diff coordinate");
        }
    }
    validate_sha256(&inventory.inventory_sha256, "inventory_sha256")?;
    if inventory.inventory_sha256 != diff_inventory_digest(inventory)? {
        return fault(GraphFaultCode::Digest, "diff inventory digest differs");
    }
    Ok(())
}

pub fn validate_change_set_manifest(
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
) -> Result<(), GraphFault> {
    validate_diff_inventory(inventory)?;
    if manifest.profile != CHANGE_SET_PROFILE {
        return fault(GraphFaultCode::Profile, "change set profile differs");
    }
    validate_encoded_bound(manifest, MAX_CHANGE_SET_BYTES, "change set")?;
    validate_uuid(&manifest.change_set_uuid, "change_set_uuid")?;
    validate_uuid(&manifest.turn_uuid, "turn_uuid")?;
    validate_uuid(&manifest.conversation_uuid, "conversation_uuid")?;
    validate_semantic_id(&manifest.repository_id, "repository_id")?;
    validate_branch_ref(&manifest.branch_ref)?;
    validate_commit(&manifest.predecessor_commit, "predecessor_commit")?;
    validate_bookend(
        manifest.publication_state,
        manifest.resulting_commit.as_deref(),
    )?;
    if manifest.repository_id != inventory.repository_id
        || manifest.branch_ref != inventory.branch_ref
        || manifest.predecessor_commit != inventory.predecessor_commit
        || manifest.inventory_sha256 != inventory.inventory_sha256
    {
        return fault(
            GraphFaultCode::Inventory,
            "change set does not join the independent inventory",
        );
    }
    if manifest.authority != VerificationAuthority::VerificationOnly || manifest.physical_contact {
        return fault(
            GraphFaultCode::Authority,
            "change set widens verification-only authority",
        );
    }

    let node_kinds = validate_nodes(&manifest.nodes)?;
    validate_edges(&manifest.edges, &node_kinds)?;
    validate_events(manifest, inventory, &node_kinds)?;
    validate_foreign_exclusions(manifest, inventory)?;
    validate_sha256(&manifest.change_set_sha256, "change_set_sha256")?;
    if manifest.change_set_sha256 != change_set_manifest_digest(manifest)? {
        return fault(GraphFaultCode::Digest, "change set digest differs");
    }
    Ok(())
}

pub fn compile_sjs_repository_graph_verification(
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
) -> Result<VerificationReceipt, GraphFault> {
    validate_change_set_manifest(manifest, inventory)?;
    let covered = inventory.entries.len();
    let mut receipt = VerificationReceipt {
        profile: VERIFICATION_RECEIPT_PROFILE.to_owned(),
        change_set_uuid: manifest.change_set_uuid.clone(),
        change_set_sha256: manifest.change_set_sha256.clone(),
        inventory_sha256: inventory.inventory_sha256.clone(),
        repository_id: manifest.repository_id.clone(),
        diff_entry_count: bounded_count(inventory.entries.len(), "diff entries")?,
        graph_node_count: bounded_count(manifest.nodes.len(), "graph nodes")?,
        graph_edge_count: bounded_count(manifest.edges.len(), "graph edges")?,
        element_event_count: bounded_count(manifest.events.len(), "element events")?,
        covered_change_count: bounded_count(covered, "covered changes")?,
        foreign_exclusion_count: bounded_count(
            manifest.foreign_exclusions.len(),
            "foreign exclusions",
        )?,
        complete_coverage: true,
        authority: VerificationAuthority::VerificationOnly,
        physical_contact: false,
        nonauthority: NONAUTHORITY.to_owned(),
        result_sha256: String::new(),
    };
    receipt.result_sha256 = verification_receipt_digest(&receipt)?;
    Ok(receipt)
}

pub fn validate_verification_receipt(
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
    receipt: &VerificationReceipt,
) -> Result<(), GraphFault> {
    let expected = compile_sjs_repository_graph_verification(manifest, inventory)?;
    if receipt != &expected {
        return fault(
            GraphFaultCode::Authority,
            "verification receipt replay differs",
        );
    }
    validate_encoded_bound(receipt, MAX_RECEIPT_BYTES, "verification receipt")
}

pub fn to_diff_inventory_machine_form(inventory: &DiffInventory) -> Result<Vec<u8>, GraphFault> {
    validate_diff_inventory(inventory)?;
    serialize_bounded(inventory, MAX_DIFF_INVENTORY_BYTES, "diff inventory")
}

pub fn from_diff_inventory_machine_form(bytes: &[u8]) -> Result<DiffInventory, GraphFault> {
    let inventory = deserialize_bounded(bytes, MAX_DIFF_INVENTORY_BYTES, "diff inventory")?;
    validate_diff_inventory(&inventory)?;
    Ok(inventory)
}

pub fn to_change_set_machine_form(
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
) -> Result<Vec<u8>, GraphFault> {
    validate_change_set_manifest(manifest, inventory)?;
    serialize_bounded(manifest, MAX_CHANGE_SET_BYTES, "change set")
}

pub fn from_change_set_machine_form(
    bytes: &[u8],
    inventory: &DiffInventory,
) -> Result<ChangeSetManifest, GraphFault> {
    let manifest = deserialize_bounded(bytes, MAX_CHANGE_SET_BYTES, "change set")?;
    validate_change_set_manifest(&manifest, inventory)?;
    Ok(manifest)
}

pub fn to_verification_receipt_machine_form(
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
    receipt: &VerificationReceipt,
) -> Result<Vec<u8>, GraphFault> {
    validate_verification_receipt(manifest, inventory, receipt)?;
    serialize_bounded(receipt, MAX_RECEIPT_BYTES, "verification receipt")
}

pub fn from_verification_receipt_machine_form(
    bytes: &[u8],
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
) -> Result<VerificationReceipt, GraphFault> {
    let receipt = deserialize_bounded(bytes, MAX_RECEIPT_BYTES, "verification receipt")?;
    validate_verification_receipt(manifest, inventory, &receipt)?;
    Ok(receipt)
}

fn validate_diff_entry(entry: &DiffEntry) -> Result<(), GraphFault> {
    validate_diff_coordinate(&entry.coordinate())?;
    validate_optional_sha256(entry.before_sha256.as_deref(), "before_sha256")?;
    validate_optional_sha256(entry.after_sha256.as_deref(), "after_sha256")?;
    let shape_ok = match entry.status {
        DiffStatus::Added => {
            entry.old_path.is_none()
                && entry.new_path.is_some()
                && entry.before_sha256.is_none()
                && entry.after_sha256.is_some()
        }
        DiffStatus::Modified | DiffStatus::GeneratedRefresh => {
            entry.old_path.is_none()
                && entry.new_path.is_some()
                && entry.before_sha256.is_some()
                && entry.after_sha256.is_some()
        }
        DiffStatus::Deleted => {
            entry.old_path.is_some()
                && entry.new_path.is_none()
                && entry.before_sha256.is_some()
                && entry.after_sha256.is_none()
        }
        DiffStatus::Renamed => {
            entry.old_path.is_some()
                && entry.new_path.is_some()
                && entry.old_path != entry.new_path
                && entry.before_sha256.is_some()
                && entry.after_sha256.is_some()
        }
    };
    if !shape_ok {
        return fault(
            GraphFaultCode::Inventory,
            "diff entry status and identity shape differ",
        );
    }
    Ok(())
}

fn validate_diff_coordinate(coordinate: &DiffCoordinate) -> Result<(), GraphFault> {
    if let Some(path) = &coordinate.old_path {
        validate_repository_path(path, "old_path")?;
    }
    if let Some(path) = &coordinate.new_path {
        validate_repository_path(path, "new_path")?;
    }
    let shape_ok = match coordinate.status {
        DiffStatus::Added | DiffStatus::Modified | DiffStatus::GeneratedRefresh => {
            coordinate.old_path.is_none() && coordinate.new_path.is_some()
        }
        DiffStatus::Deleted => coordinate.old_path.is_some() && coordinate.new_path.is_none(),
        DiffStatus::Renamed => {
            coordinate.old_path.is_some()
                && coordinate.new_path.is_some()
                && coordinate.old_path != coordinate.new_path
        }
    };
    if !shape_ok {
        return fault(GraphFaultCode::Inventory, "diff coordinate shape differs");
    }
    Ok(())
}

fn validate_nodes(nodes: &[GraphNode]) -> Result<HashMap<String, GraphNodeKind>, GraphFault> {
    if nodes.is_empty() || nodes.len() > MAX_NODES {
        return fault(
            GraphFaultCode::Resource,
            "graph node count is empty or over bound",
        );
    }
    let mut node_kinds = HashMap::new();
    for node in nodes {
        validate_semantic_id(&node.node_id, "node_id")?;
        if node_kinds.insert(node.node_id.clone(), node.kind).is_some() {
            return fault(GraphFaultCode::Graph, "duplicate graph node ID");
        }
        match (&node.repository_path, &node.content_sha256) {
            (Some(path), Some(sha256)) => {
                validate_repository_path(path, "graph node repository_path")?;
                validate_sha256(sha256, "graph node content_sha256")?;
            }
            (None, None) => {}
            _ => {
                return fault(
                    GraphFaultCode::Graph,
                    "graph node path and digest coupling differs",
                );
            }
        }
    }
    Ok(node_kinds)
}

fn validate_edges(
    edges: &[GraphEdge],
    node_kinds: &HashMap<String, GraphNodeKind>,
) -> Result<(), GraphFault> {
    if edges.is_empty() || edges.len() > MAX_EDGES {
        return fault(
            GraphFaultCode::Resource,
            "graph edge count is empty or over bound",
        );
    }
    let mut edge_ids = HashSet::new();
    let mut triples = HashSet::new();
    for edge in edges {
        validate_semantic_id(&edge.edge_id, "edge_id")?;
        if !edge_ids.insert(edge.edge_id.clone()) {
            return fault(GraphFaultCode::Graph, "duplicate graph edge ID");
        }
        if edge.source_node_id == edge.target_node_id {
            return fault(GraphFaultCode::Graph, "self graph edge is forbidden");
        }
        if !node_kinds.contains_key(&edge.source_node_id)
            || !node_kinds.contains_key(&edge.target_node_id)
        {
            return fault(GraphFaultCode::Graph, "dangling graph edge endpoint");
        }
        if !triples.insert((edge.kind, &edge.source_node_id, &edge.target_node_id)) {
            return fault(GraphFaultCode::Graph, "duplicate graph edge triple");
        }
    }
    Ok(())
}

fn validate_events(
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
    node_kinds: &HashMap<String, GraphNodeKind>,
) -> Result<(), GraphFault> {
    if manifest.events.is_empty() || manifest.events.len() > MAX_EVENTS {
        return fault(
            GraphFaultCode::Resource,
            "element event count is empty or over bound",
        );
    }
    let inventory_coordinates: HashSet<_> = inventory
        .entries
        .iter()
        .map(DiffEntry::coordinate)
        .collect();
    let mut covered_coordinates = HashSet::new();
    let mut event_uuids = HashSet::new();
    let mut element_ids = HashSet::new();

    for event in &manifest.events {
        validate_event(
            event,
            manifest,
            &inventory_coordinates,
            node_kinds,
            &manifest.edges,
        )?;
        if !event_uuids.insert(event.event_uuid.clone()) {
            return fault(GraphFaultCode::Event, "duplicate event UUID");
        }
        if !element_ids.insert(event.element_id.clone()) {
            return fault(
                GraphFaultCode::Event,
                "duplicate element ID in one change set",
            );
        }
        covered_coordinates.extend(event.covered_changes.iter().cloned());
    }

    if covered_coordinates != inventory_coordinates {
        return fault(
            GraphFaultCode::Coverage,
            "element events do not exactly cover inventory coordinates",
        );
    }
    Ok(())
}

fn validate_event(
    event: &ElementHistoryEvent,
    manifest: &ChangeSetManifest,
    inventory_coordinates: &HashSet<DiffCoordinate>,
    node_kinds: &HashMap<String, GraphNodeKind>,
    edges: &[GraphEdge],
) -> Result<(), GraphFault> {
    if event.profile != ELEMENT_EVENT_PROFILE {
        return fault(GraphFaultCode::Profile, "element event profile differs");
    }
    validate_uuid(&event.event_uuid, "event_uuid")?;
    validate_uuid(&event.turn_uuid, "event turn_uuid")?;
    validate_uuid(&event.conversation_uuid, "event conversation_uuid")?;
    validate_uuid(&event.change_set_uuid, "event change_set_uuid")?;
    validate_semantic_id(&event.event_node_id, "event_node_id")?;
    validate_semantic_id(&event.element_id, "element_id")?;
    validate_semantic_id(&event.element_node_id, "element_node_id")?;
    if event.turn_uuid != manifest.turn_uuid
        || event.conversation_uuid != manifest.conversation_uuid
        || event.change_set_uuid != manifest.change_set_uuid
    {
        return fault(GraphFaultCode::Event, "event lineage differs");
    }
    require_node_kind(
        node_kinds,
        &event.event_node_id,
        GraphNodeKind::ElementHistoryEvent,
        "event node",
    )?;
    require_node_kind(
        node_kinds,
        &event.element_node_id,
        GraphNodeKind::Element,
        "element node",
    )?;
    if !edges.iter().any(|edge| {
        edge.kind == GraphEdgeKind::Modifies
            && edge.source_node_id == event.event_node_id
            && edge.target_node_id == event.element_node_id
    }) {
        return fault(
            GraphFaultCode::Graph,
            "event lacks modifies edge to element node",
        );
    }

    if event.covered_changes.is_empty() || event.covered_changes.len() > MAX_EVENT_CHANGES {
        return fault(
            GraphFaultCode::Resource,
            "event coverage count is empty or over bound",
        );
    }
    let mut event_coordinates = HashSet::new();
    for coordinate in &event.covered_changes {
        validate_diff_coordinate(coordinate)?;
        if !event_coordinates.insert(coordinate.clone()) {
            return fault(
                GraphFaultCode::Coverage,
                "duplicate event coverage coordinate",
            );
        }
        if !inventory_coordinates.contains(coordinate) {
            return fault(
                GraphFaultCode::Coverage,
                "event coverage is absent from inventory",
            );
        }
        if !operation_matches_status(event.operation, coordinate.status) {
            return fault(
                GraphFaultCode::Coverage,
                "event operation and diff status differ",
            );
        }
    }

    validate_event_refs(event, node_kinds)?;
    validate_text(&event.reason_summary, "reason_summary")?;
    validate_optional_sha256(event.before_sha256.as_deref(), "event before_sha256")?;
    validate_optional_sha256(event.after_sha256.as_deref(), "event after_sha256")?;
    validate_event_identity_shape(event)?;
    validate_text_list(&event.nonclaims, "nonclaims")?;
    validate_text_list(&event.unresolved_frontier, "unresolved_frontier")?;
    validate_sha256(&event.event_sha256, "event_sha256")?;
    if event.event_sha256 != element_history_event_digest(event)? {
        return fault(GraphFaultCode::Digest, "element event digest differs");
    }
    Ok(())
}

fn validate_event_refs(
    event: &ElementHistoryEvent,
    node_kinds: &HashMap<String, GraphNodeKind>,
) -> Result<(), GraphFault> {
    validate_ref_set(
        &event.source_node_ids,
        GraphNodeKind::Source,
        node_kinds,
        "source",
    )?;
    validate_ref_set(
        &event.requirement_node_ids,
        GraphNodeKind::Requirement,
        node_kinds,
        "requirement",
    )?;
    validate_ref_set(
        &event.constraint_node_ids,
        GraphNodeKind::Constraint,
        node_kinds,
        "constraint",
    )?;
    validate_ref_set(
        &event.justification_node_ids,
        GraphNodeKind::Justification,
        node_kinds,
        "justification",
    )?;
    validate_ref_set(
        &event.plan_node_ids,
        GraphNodeKind::Plan,
        node_kinds,
        "plan",
    )?;
    validate_ref_set(
        &event.implementation_node_ids,
        GraphNodeKind::ImplementationArtifact,
        node_kinds,
        "implementation",
    )?;
    validate_ref_set(
        &event.evidence_node_ids,
        GraphNodeKind::Evidence,
        node_kinds,
        "evidence",
    )?;
    validate_ref_set(
        &event.proof_node_ids,
        GraphNodeKind::Proof,
        node_kinds,
        "proof",
    )?;
    validate_ref_set(
        &event.narrative_node_ids,
        GraphNodeKind::NarrativeTurn,
        node_kinds,
        "narrative",
    )?;
    validate_ref_set(
        &event.frontier_node_ids,
        GraphNodeKind::Frontier,
        node_kinds,
        "frontier",
    )?;
    Ok(())
}

fn validate_ref_set(
    refs: &[String],
    expected_kind: GraphNodeKind,
    node_kinds: &HashMap<String, GraphNodeKind>,
    label: &str,
) -> Result<(), GraphFault> {
    if refs.is_empty() || refs.len() > MAX_EVENT_REFS {
        return fault(
            GraphFaultCode::Resource,
            format!("{label} ref count is empty or over bound"),
        );
    }
    let mut unique = HashSet::new();
    for node_id in refs {
        validate_semantic_id(node_id, label)?;
        if !unique.insert(node_id) {
            return fault(GraphFaultCode::Event, format!("duplicate {label} ref"));
        }
        require_node_kind(node_kinds, node_id, expected_kind, label)?;
    }
    Ok(())
}

fn require_node_kind(
    node_kinds: &HashMap<String, GraphNodeKind>,
    node_id: &str,
    expected_kind: GraphNodeKind,
    label: &str,
) -> Result<(), GraphFault> {
    if node_kinds.get(node_id) != Some(&expected_kind) {
        return fault(GraphFaultCode::Event, format!("{label} node kind differs"));
    }
    Ok(())
}

fn validate_event_identity_shape(event: &ElementHistoryEvent) -> Result<(), GraphFault> {
    let identity_ok = match event.operation {
        ElementOperation::Add | ElementOperation::Restore => {
            event.before_sha256.is_none() && event.after_sha256.is_some()
        }
        ElementOperation::Delete => event.before_sha256.is_some() && event.after_sha256.is_none(),
        _ => event.before_sha256.is_some() && event.after_sha256.is_some(),
    };
    if !identity_ok {
        return fault(
            GraphFaultCode::Event,
            "event operation and identity shape differ",
        );
    }
    if event.tombstone != (event.operation == ElementOperation::Delete) {
        return fault(GraphFaultCode::Event, "event tombstone state differs");
    }
    if event.generated != (event.operation == ElementOperation::GeneratedRefresh) {
        return fault(GraphFaultCode::Event, "event generated state differs");
    }
    Ok(())
}

fn operation_matches_status(operation: ElementOperation, status: DiffStatus) -> bool {
    match status {
        DiffStatus::Added => matches!(operation, ElementOperation::Add | ElementOperation::Restore),
        DiffStatus::Modified => matches!(
            operation,
            ElementOperation::Modify
                | ElementOperation::Correct
                | ElementOperation::Supersede
                | ElementOperation::Invalidate
        ),
        DiffStatus::Deleted => operation == ElementOperation::Delete,
        DiffStatus::Renamed => {
            matches!(operation, ElementOperation::Rename | ElementOperation::Move)
        }
        DiffStatus::GeneratedRefresh => operation == ElementOperation::GeneratedRefresh,
    }
}

fn validate_foreign_exclusions(
    manifest: &ChangeSetManifest,
    inventory: &DiffInventory,
) -> Result<(), GraphFault> {
    if manifest.foreign_exclusions.len() > MAX_FOREIGN_EXCLUSIONS {
        return fault(
            GraphFaultCode::Resource,
            "foreign exclusion count is over bound",
        );
    }
    let mut owned_paths = HashSet::new();
    for entry in &inventory.entries {
        if let Some(path) = &entry.old_path {
            owned_paths.insert(path.as_str());
        }
        if let Some(path) = &entry.new_path {
            owned_paths.insert(path.as_str());
        }
    }
    for node in &manifest.nodes {
        if let Some(path) = &node.repository_path {
            owned_paths.insert(path.as_str());
        }
    }
    let mut foreign_paths = HashSet::new();
    for exclusion in &manifest.foreign_exclusions {
        validate_repository_path(&exclusion.path, "foreign exclusion path")?;
        validate_text(&exclusion.reason, "foreign exclusion reason")?;
        if !foreign_paths.insert(exclusion.path.as_str()) {
            return fault(GraphFaultCode::Foreign, "duplicate foreign exclusion");
        }
        if owned_paths.contains(exclusion.path.as_str()) {
            return fault(
                GraphFaultCode::Foreign,
                "foreign exclusion overlaps owned graph or inventory path",
            );
        }
    }
    Ok(())
}

fn validate_bookend(
    state: PublicationState,
    resulting_commit: Option<&str>,
) -> Result<(), GraphFault> {
    match (state, resulting_commit) {
        (PublicationState::Candidate, None) => Ok(()),
        (PublicationState::Committed | PublicationState::Published, Some(commit)) => {
            validate_commit(commit, "resulting_commit")
        }
        _ => fault(
            GraphFaultCode::Identity,
            "publication state and resulting commit differ",
        ),
    }
}

fn validate_repository_path(path: &str, label: &str) -> Result<(), GraphFault> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.contains(':')
        || path.contains("//")
    {
        return fault(GraphFaultCode::Path, format!("{label} is not normalized"));
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.chars().any(char::is_control)
        {
            return fault(
                GraphFaultCode::Path,
                format!("{label} has unsafe component"),
            );
        }
    }
    Ok(())
}

fn validate_semantic_id(value: &str, label: &str) -> Result<(), GraphFault> {
    if value.is_empty() || value.len() > MAX_SEMANTIC_ID_BYTES {
        return fault(GraphFaultCode::Identity, format!("{label} length differs"));
    }
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return fault(GraphFaultCode::Identity, format!("{label} is empty"));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return fault(
            GraphFaultCode::Identity,
            format!("{label} first character differs"),
        );
    }
    if characters.any(|character| {
        !character.is_ascii_lowercase()
            && !character.is_ascii_digit()
            && !matches!(character, '-' | '_' | '.' | '/' | ':')
    }) || value.contains("//")
        || value.contains("..")
        || value.ends_with('/')
        || value.ends_with(':')
    {
        return fault(GraphFaultCode::Identity, format!("{label} grammar differs"));
    }
    Ok(())
}

fn validate_uuid(value: &str, label: &str) -> Result<(), GraphFault> {
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 8 | 13 | 18 | 23)
                && !byte.is_ascii_digit()
                && !(b'a'..=b'f').contains(byte)
        })
    {
        return fault(GraphFaultCode::Identity, format!("{label} grammar differs"));
    }
    Ok(())
}

fn validate_commit(value: &str, label: &str) -> Result<(), GraphFault> {
    if value.len() != 40
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return fault(GraphFaultCode::Identity, format!("{label} grammar differs"));
    }
    Ok(())
}

fn validate_branch_ref(value: &str) -> Result<(), GraphFault> {
    let Some(rest) = value.strip_prefix("refs/heads/") else {
        return fault(GraphFaultCode::Identity, "branch_ref prefix differs");
    };
    if rest.is_empty()
        || rest.len() > MAX_SEMANTIC_ID_BYTES
        || rest.starts_with('/')
        || rest.ends_with('/')
        || rest.contains("//")
        || rest.contains("..")
        || rest.contains("@{")
        || rest.chars().any(|character| {
            !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.' | '/')
        })
    {
        return fault(GraphFaultCode::Identity, "branch_ref grammar differs");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), GraphFault> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'A'..=b'F').contains(&byte))
    {
        return fault(GraphFaultCode::Identity, format!("{label} grammar differs"));
    }
    Ok(())
}

fn validate_optional_sha256(value: Option<&str>, label: &str) -> Result<(), GraphFault> {
    if let Some(value) = value {
        validate_sha256(value, label)?;
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), GraphFault> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(|character| character == '\0')
    {
        return fault(GraphFaultCode::Resource, format!("{label} bound differs"));
    }
    Ok(())
}

fn validate_text_list(values: &[String], label: &str) -> Result<(), GraphFault> {
    if values.is_empty() || values.len() > MAX_TEXT_ITEMS {
        return fault(
            GraphFaultCode::Resource,
            format!("{label} count is empty or over bound"),
        );
    }
    let mut unique = HashSet::new();
    for value in values {
        validate_text(value, label)?;
        if !unique.insert(value) {
            return fault(GraphFaultCode::Event, format!("duplicate {label}"));
        }
    }
    Ok(())
}

fn validate_encoded_bound<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &str,
) -> Result<(), GraphFault> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| graph_error(GraphFaultCode::Serialization, error.to_string()))?;
    if bytes.len() > maximum {
        return fault(
            GraphFaultCode::Resource,
            format!("{label} byte bound exceeded"),
        );
    }
    Ok(())
}

fn serialize_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, GraphFault> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| graph_error(GraphFaultCode::Serialization, error.to_string()))?;
    if bytes.len() > maximum {
        return fault(
            GraphFaultCode::Resource,
            format!("{label} byte bound exceeded"),
        );
    }
    Ok(bytes)
}

fn deserialize_bounded<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
    label: &str,
) -> Result<T, GraphFault> {
    if bytes.len() > maximum {
        return fault(
            GraphFaultCode::Resource,
            format!("{label} byte bound exceeded"),
        );
    }
    serde_json::from_slice(bytes)
        .map_err(|error| graph_error(GraphFaultCode::Serialization, error.to_string()))
}

fn digest_form<T: Serialize>(domain: &[u8], value: &T) -> Result<String, GraphFault> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| graph_error(GraphFaultCode::Serialization, error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect())
}

fn bounded_count(count: usize, label: &str) -> Result<u32, GraphFault> {
    u32::try_from(count)
        .map_err(|_| graph_error(GraphFaultCode::Resource, format!("{label} count overflow")))
}

fn fault<T>(code: GraphFaultCode, message: impl Into<String>) -> Result<T, GraphFault> {
    Err(graph_error(code, message))
}

fn graph_error(code: GraphFaultCode, message: impl Into<String>) -> GraphFault {
    GraphFault {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const SHA_B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const SHA_C: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

    fn content_node(node_id: &str, kind: GraphNodeKind, path: &str) -> GraphNode {
        GraphNode {
            node_id: node_id.to_owned(),
            kind,
            repository_path: Some(path.to_owned()),
            content_sha256: Some(SHA_A.to_owned()),
        }
    }

    fn semantic_node(node_id: &str, kind: GraphNodeKind) -> GraphNode {
        GraphNode {
            node_id: node_id.to_owned(),
            kind,
            repository_path: None,
            content_sha256: None,
        }
    }

    fn valid_inventory() -> DiffInventory {
        let mut inventory = DiffInventory {
            profile: DIFF_INVENTORY_PROFILE.to_owned(),
            repository_id: "cattailfarmer/cantor".to_owned(),
            branch_ref: "refs/heads/codex/self-hosted-corpus".to_owned(),
            predecessor_commit: "2e802dc9f10b9902543d670ab6a183c70e04a24e".to_owned(),
            entries: vec![DiffEntry {
                status: DiffStatus::Added,
                old_path: None,
                new_path: Some("crates/example/src/graph.rs".to_owned()),
                before_sha256: None,
                after_sha256: Some(SHA_B.to_owned()),
            }],
            inventory_sha256: String::new(),
        };
        inventory.inventory_sha256 = diff_inventory_digest(&inventory).unwrap();
        inventory
    }

    fn valid_nodes() -> Vec<GraphNode> {
        vec![
            content_node(
                "source:graph",
                GraphNodeKind::Source,
                "source_documents/graph.sop",
            ),
            semantic_node("requirement:csg-001", GraphNodeKind::Requirement),
            semantic_node("constraint:c01", GraphNodeKind::Constraint),
            content_node(
                "justification:graph",
                GraphNodeKind::Justification,
                "justifications/graph.sop",
            ),
            content_node("plan:graph", GraphNodeKind::Plan, "plans/graph.sop"),
            semantic_node("element:graph-module", GraphNodeKind::Element),
            semantic_node("event:graph-module", GraphNodeKind::ElementHistoryEvent),
            content_node(
                "implementation:graph-module",
                GraphNodeKind::ImplementationArtifact,
                "crates/example/src/graph.rs",
            ),
            content_node(
                "evidence:graph",
                GraphNodeKind::Evidence,
                "evidence/graph.json",
            ),
            content_node("proof:graph", GraphNodeKind::Proof, "proofs/graph.sop"),
            content_node(
                "narrative:graph",
                GraphNodeKind::NarrativeTurn,
                "narrative/turns/graph.sop",
            ),
            semantic_node("frontier:physical-git", GraphNodeKind::Frontier),
        ]
    }

    fn valid_event() -> ElementHistoryEvent {
        let mut event = ElementHistoryEvent {
            profile: ELEMENT_EVENT_PROFILE.to_owned(),
            event_uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
            event_node_id: "event:graph-module".to_owned(),
            element_id: "cantor.sjs.graph.module".to_owned(),
            element_node_id: "element:graph-module".to_owned(),
            operation: ElementOperation::Add,
            turn_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            conversation_uuid: "33333333-3333-4333-8333-333333333333".to_owned(),
            change_set_uuid: "44444444-4444-4444-8444-444444444444".to_owned(),
            covered_changes: vec![DiffCoordinate {
                status: DiffStatus::Added,
                old_path: None,
                new_path: Some("crates/example/src/graph.rs".to_owned()),
            }],
            source_node_ids: vec!["source:graph".to_owned()],
            requirement_node_ids: vec!["requirement:csg-001".to_owned()],
            constraint_node_ids: vec!["constraint:c01".to_owned()],
            justification_node_ids: vec!["justification:graph".to_owned()],
            plan_node_ids: vec!["plan:graph".to_owned()],
            implementation_node_ids: vec!["implementation:graph-module".to_owned()],
            evidence_node_ids: vec!["evidence:graph".to_owned()],
            proof_node_ids: vec!["proof:graph".to_owned()],
            narrative_node_ids: vec!["narrative:graph".to_owned()],
            frontier_node_ids: vec!["frontier:physical-git".to_owned()],
            reason_summary: "Add the pure graph verifier required by signed SJS.".to_owned(),
            before_sha256: None,
            after_sha256: Some(SHA_B.to_owned()),
            tombstone: false,
            generated: false,
            nonclaims: vec!["No physical Git observation authority.".to_owned()],
            unresolved_frontier: vec!["Physical staged-diff capture remains separate.".to_owned()],
            event_sha256: String::new(),
        };
        event.event_sha256 = element_history_event_digest(&event).unwrap();
        event
    }

    fn valid_manifest(inventory: &DiffInventory) -> ChangeSetManifest {
        let mut manifest = ChangeSetManifest {
            profile: CHANGE_SET_PROFILE.to_owned(),
            change_set_uuid: "44444444-4444-4444-8444-444444444444".to_owned(),
            repository_id: inventory.repository_id.clone(),
            branch_ref: inventory.branch_ref.clone(),
            predecessor_commit: inventory.predecessor_commit.clone(),
            resulting_commit: None,
            publication_state: PublicationState::Candidate,
            turn_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            conversation_uuid: "33333333-3333-4333-8333-333333333333".to_owned(),
            inventory_sha256: inventory.inventory_sha256.clone(),
            nodes: valid_nodes(),
            edges: vec![GraphEdge {
                edge_id: "edge:event-modifies-element".to_owned(),
                kind: GraphEdgeKind::Modifies,
                source_node_id: "event:graph-module".to_owned(),
                target_node_id: "element:graph-module".to_owned(),
            }],
            events: vec![valid_event()],
            foreign_exclusions: vec![ForeignExclusion {
                path: "AGENTS.md".to_owned(),
                reason: "Pre-existing foreign tracked edit.".to_owned(),
            }],
            authority: VerificationAuthority::VerificationOnly,
            physical_contact: false,
            change_set_sha256: String::new(),
        };
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        manifest
    }

    #[test]
    fn valid_graph_compiles_and_replays_deterministically() {
        let inventory = valid_inventory();
        let manifest = valid_manifest(&inventory);
        let first = compile_sjs_repository_graph_verification(&manifest, &inventory).unwrap();
        let second = compile_sjs_repository_graph_verification(&manifest, &inventory).unwrap();
        assert_eq!(first, second);
        assert!(first.complete_coverage);
        assert!(!first.physical_contact);
        assert_eq!(first.authority, VerificationAuthority::VerificationOnly);
        validate_verification_receipt(&manifest, &inventory, &first).unwrap();
    }

    #[test]
    fn strict_machine_forms_refuse_unknown_fields() {
        let inventory = valid_inventory();
        let mut value = serde_json::to_value(&inventory).unwrap();
        value["unknown"] = serde_json::json!(true);
        let error =
            from_diff_inventory_machine_form(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(error.code, GraphFaultCode::Serialization);
    }

    #[test]
    fn inventory_refuses_path_traversal() {
        let mut inventory = valid_inventory();
        inventory.entries[0].new_path = Some("../escape".to_owned());
        inventory.inventory_sha256 = diff_inventory_digest(&inventory).unwrap();
        assert_eq!(
            validate_diff_inventory(&inventory).unwrap_err().code,
            GraphFaultCode::Path
        );
    }

    #[test]
    fn manifest_refuses_missing_coverage() {
        let inventory = valid_inventory();
        let mut manifest = valid_manifest(&inventory);
        manifest.events[0].covered_changes[0].new_path = Some("other.rs".to_owned());
        manifest.events[0].event_sha256 =
            element_history_event_digest(&manifest.events[0]).unwrap();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        assert_eq!(
            validate_change_set_manifest(&manifest, &inventory)
                .unwrap_err()
                .code,
            GraphFaultCode::Coverage
        );
    }

    #[test]
    fn manifest_refuses_wrong_typed_reference() {
        let inventory = valid_inventory();
        let mut manifest = valid_manifest(&inventory);
        manifest.events[0].proof_node_ids = vec!["plan:graph".to_owned()];
        manifest.events[0].event_sha256 =
            element_history_event_digest(&manifest.events[0]).unwrap();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        assert_eq!(
            validate_change_set_manifest(&manifest, &inventory)
                .unwrap_err()
                .code,
            GraphFaultCode::Event
        );
    }

    #[test]
    fn manifest_refuses_dangling_edge() {
        let inventory = valid_inventory();
        let mut manifest = valid_manifest(&inventory);
        manifest.edges[0].target_node_id = "element:absent".to_owned();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        assert_eq!(
            validate_change_set_manifest(&manifest, &inventory)
                .unwrap_err()
                .code,
            GraphFaultCode::Graph
        );
    }

    #[test]
    fn manifest_refuses_foreign_overlap() {
        let inventory = valid_inventory();
        let mut manifest = valid_manifest(&inventory);
        manifest.foreign_exclusions[0].path = "crates/example/src/graph.rs".to_owned();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        assert_eq!(
            validate_change_set_manifest(&manifest, &inventory)
                .unwrap_err()
                .code,
            GraphFaultCode::Foreign
        );
    }

    #[test]
    fn manifest_refuses_event_digest_tamper() {
        let inventory = valid_inventory();
        let mut manifest = valid_manifest(&inventory);
        manifest.events[0].reason_summary.push_str(" tampered");
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        assert_eq!(
            validate_change_set_manifest(&manifest, &inventory)
                .unwrap_err()
                .code,
            GraphFaultCode::Digest
        );
    }

    #[test]
    fn receipt_refuses_replay_tamper() {
        let inventory = valid_inventory();
        let manifest = valid_manifest(&inventory);
        let mut receipt = compile_sjs_repository_graph_verification(&manifest, &inventory).unwrap();
        receipt.complete_coverage = false;
        receipt.result_sha256 = verification_receipt_digest(&receipt).unwrap();
        assert_eq!(
            validate_verification_receipt(&manifest, &inventory, &receipt)
                .unwrap_err()
                .code,
            GraphFaultCode::Authority
        );
    }

    #[test]
    fn generated_refresh_requires_generated_event() {
        let mut inventory = valid_inventory();
        inventory.entries[0] = DiffEntry {
            status: DiffStatus::GeneratedRefresh,
            old_path: None,
            new_path: Some("crates/example/src/graph.rs".to_owned()),
            before_sha256: Some(SHA_A.to_owned()),
            after_sha256: Some(SHA_B.to_owned()),
        };
        inventory.inventory_sha256 = diff_inventory_digest(&inventory).unwrap();
        let mut manifest = valid_manifest(&inventory);
        manifest.events[0].covered_changes[0].status = DiffStatus::GeneratedRefresh;
        manifest.events[0].before_sha256 = Some(SHA_A.to_owned());
        manifest.events[0].event_sha256 =
            element_history_event_digest(&manifest.events[0]).unwrap();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        assert_eq!(
            validate_change_set_manifest(&manifest, &inventory)
                .unwrap_err()
                .code,
            GraphFaultCode::Coverage
        );

        manifest.events[0].operation = ElementOperation::GeneratedRefresh;
        manifest.events[0].generated = true;
        manifest.events[0].event_sha256 =
            element_history_event_digest(&manifest.events[0]).unwrap();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        validate_change_set_manifest(&manifest, &inventory).unwrap();
    }

    #[test]
    fn deletion_requires_tombstone() {
        let mut inventory = valid_inventory();
        inventory.entries[0] = DiffEntry {
            status: DiffStatus::Deleted,
            old_path: Some("crates/example/src/graph.rs".to_owned()),
            new_path: None,
            before_sha256: Some(SHA_A.to_owned()),
            after_sha256: None,
        };
        inventory.inventory_sha256 = diff_inventory_digest(&inventory).unwrap();
        let mut manifest = valid_manifest(&inventory);
        let event = &mut manifest.events[0];
        event.operation = ElementOperation::Delete;
        event.covered_changes[0] = inventory.entries[0].coordinate();
        event.before_sha256 = Some(SHA_A.to_owned());
        event.after_sha256 = None;
        event.event_sha256 = element_history_event_digest(event).unwrap();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        assert_eq!(
            validate_change_set_manifest(&manifest, &inventory)
                .unwrap_err()
                .code,
            GraphFaultCode::Event
        );

        manifest.events[0].tombstone = true;
        manifest.events[0].event_sha256 =
            element_history_event_digest(&manifest.events[0]).unwrap();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        validate_change_set_manifest(&manifest, &inventory).unwrap();
    }

    #[test]
    fn renamed_entry_preserves_element_identity() {
        let mut inventory = valid_inventory();
        inventory.entries[0] = DiffEntry {
            status: DiffStatus::Renamed,
            old_path: Some("crates/example/src/old.rs".to_owned()),
            new_path: Some("crates/example/src/graph.rs".to_owned()),
            before_sha256: Some(SHA_A.to_owned()),
            after_sha256: Some(SHA_C.to_owned()),
        };
        inventory.inventory_sha256 = diff_inventory_digest(&inventory).unwrap();
        let mut manifest = valid_manifest(&inventory);
        let event = &mut manifest.events[0];
        event.operation = ElementOperation::Rename;
        event.covered_changes[0] = inventory.entries[0].coordinate();
        event.before_sha256 = Some(SHA_A.to_owned());
        event.after_sha256 = Some(SHA_C.to_owned());
        event.event_sha256 = element_history_event_digest(event).unwrap();
        manifest.change_set_sha256 = change_set_manifest_digest(&manifest).unwrap();
        validate_change_set_manifest(&manifest, &inventory).unwrap();
    }

    #[test]
    fn machine_forms_round_trip_exactly() {
        let inventory = valid_inventory();
        let manifest = valid_manifest(&inventory);
        let receipt = compile_sjs_repository_graph_verification(&manifest, &inventory).unwrap();
        let inventory_bytes = to_diff_inventory_machine_form(&inventory).unwrap();
        assert_eq!(
            from_diff_inventory_machine_form(&inventory_bytes).unwrap(),
            inventory
        );
        let manifest_bytes = to_change_set_machine_form(&manifest, &inventory).unwrap();
        assert_eq!(
            from_change_set_machine_form(&manifest_bytes, &inventory).unwrap(),
            manifest
        );
        let receipt_bytes =
            to_verification_receipt_machine_form(&manifest, &inventory, &receipt).unwrap();
        assert_eq!(
            from_verification_receipt_machine_form(&receipt_bytes, &manifest, &inventory).unwrap(),
            receipt
        );
    }
}
