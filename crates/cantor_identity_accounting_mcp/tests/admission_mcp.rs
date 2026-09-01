use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    ACCOUNTABLE_OBJECT_ADMISSION_PROFILE, ACCOUNTABLE_OBJECT_PROFILE,
    ACCOUNTING_HOST_REQUEST_PROFILE, AccountableObject, AccountableObjectAdmission,
    AccountingHostOperation, AccountingHostRequest, AccountingHostResult, CombinatoryProjection,
    ContentDigest, FacultyActivation, FacultyCycle, FacultyCycleKind, FacultyKind, FacultyLedger,
    FacultyReturn, FacultyReturnStatus, FacultyStage, IdentityBoundary, IdentityBoundaryDomain,
    ObserverDisposition, ProjectionKind, ProjectionStatus, ReferenceResolution, SemanticId,
    accounting_ledger_state_ref, finalize_accountable_object,
    finalize_accountable_object_admission, new_accounting_journal, new_identity_ledger,
};
use cantor_identity_accounting_mcp::{
    AccountingMcpStatus, IdentityAccountingMcpResponse, IdentityAccountingMcpServer, SnapshotStore,
    SnapshotStoreConfig,
};
use serde_json::{Value, json};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "cantor-admission-mcp-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
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

fn object(local: &str, source: &str) -> AccountableObject {
    finalize_accountable_object(AccountableObject {
        profile: ACCOUNTABLE_OBJECT_PROFILE.to_owned(),
        handle: sid(&format!("object:airplane/{local}")),
        object_type: sid("airplane"),
        labels: BTreeSet::from([format!("airplane {local}")]),
        differentiators: BTreeMap::from([("tail_number".to_owned(), local.to_owned())]),
        state: BTreeMap::from([("readiness".to_owned(), "proposed".to_owned())]),
        roles: BTreeSet::from([sid("role:transport")]),
        purposes: BTreeSet::from([sid("purpose:durable-admission")]),
        obligations: BTreeSet::from([sid("obligation:retain-distinction")]),
        provenance_refs: BTreeSet::from([sid(source)]),
        version: 1,
        record_digest: empty_digest(),
    })
    .unwrap()
}

fn activation(ordinal: u32, faculty: FacultyKind, stage: FacultyStage) -> FacultyActivation {
    FacultyActivation {
        activation_id: sid(&format!("activation:durable-admission/{ordinal}")),
        faculty,
        stage,
        ordinal,
        purpose: format!("{faculty:?} {stage:?}"),
        input_refs: vec![sid("proposal:durable-admission/beta")],
        unavailable_refs: Vec::new(),
    }
}

fn faculty_cycle(
    base: &cantor_core::IdentityLedger,
    candidate: &AccountableObject,
) -> FacultyCycle {
    let activations = vec![
        activation(1, FacultyKind::Observer, FacultyStage::Observe),
        activation(2, FacultyKind::Scribe, FacultyStage::Anchor),
        activation(3, FacultyKind::Honesty, FacultyStage::Bound),
        activation(4, FacultyKind::Security, FacultyStage::Bound),
        activation(5, FacultyKind::Weaver, FacultyStage::Project),
        activation(6, FacultyKind::Planner, FacultyStage::Project),
        activation(7, FacultyKind::Refiner, FacultyStage::Refine),
        activation(8, FacultyKind::Honesty, FacultyStage::Gate),
        activation(9, FacultyKind::Security, FacultyStage::Gate),
        activation(10, FacultyKind::Observer, FacultyStage::Decide),
        activation(11, FacultyKind::Scribe, FacultyStage::Inscribe),
    ];
    let mut returns = activations
        .iter()
        .map(|activation| FacultyReturn {
            activation_id: activation.activation_id.clone(),
            faculty: activation.faculty,
            status: FacultyReturnStatus::Accepted,
            output_refs: vec![sid(&format!(
                "output:durable-admission/{}",
                activation.ordinal
            ))],
            objections: Vec::new(),
            uncertainty: Vec::new(),
            ledger: FacultyLedger {
                source_refs: vec!["source:beta".to_owned()],
                grounds: vec!["exact fixture evidence".to_owned()],
                constraint_refs: vec!["IAT-01..12".to_owned()],
                retained_boundaries: vec!["transport is not truth".to_owned()],
                relation_refs: Vec::new(),
            },
        })
        .collect::<Vec<_>>();
    returns[2]
        .output_refs
        .push(sid("boundary:durable/epistemic"));
    returns[3]
        .output_refs
        .push(sid("boundary:durable/authority"));
    returns[4]
        .output_refs
        .push(sid("projection:durable/relational"));
    returns[5]
        .output_refs
        .push(sid("projection:durable/temporal"));
    let before = accounting_ledger_state_ref(&base.ledger_digest).unwrap();
    FacultyCycle {
        cycle_id: sid("cycle:durable-admission/beta"),
        kind: FacultyCycleKind::SemanticTransition,
        subject: candidate.handle.to_string(),
        purpose: "judge exact durable identity admission".to_owned(),
        before_state_ref: before.clone(),
        identity_boundaries: vec![
            IdentityBoundary {
                boundary_id: sid("boundary:durable/epistemic"),
                domain: IdentityBoundaryDomain::Epistemic,
                guarded_by: FacultyKind::Honesty,
                subject_ref: candidate.handle.clone(),
                inside: vec!["declared fixture evidence".to_owned()],
                edge_conditions: vec!["evidence changes".to_owned()],
                outside: vec!["external truth".to_owned()],
                uncertainty: Vec::new(),
            },
            IdentityBoundary {
                boundary_id: sid("boundary:durable/authority"),
                domain: IdentityBoundaryDomain::Authority,
                guarded_by: FacultyKind::Security,
                subject_ref: candidate.handle.clone(),
                inside: vec!["durable accounting custody".to_owned()],
                edge_conditions: vec!["external effect requested".to_owned()],
                outside: vec!["external effects".to_owned()],
                uncertainty: Vec::new(),
            },
        ],
        projections: vec![
            CombinatoryProjection {
                projection_id: sid("projection:durable/relational"),
                kind: ProjectionKind::Relational,
                projected_by: FacultyKind::Weaver,
                status: ProjectionStatus::Candidate,
                basis_refs: vec![before],
                candidate_refs: vec![candidate.handle.clone()],
                constraint_refs: vec!["preserve existing identity".to_owned()],
                residuals: Vec::new(),
            },
            CombinatoryProjection {
                projection_id: sid("projection:durable/temporal"),
                kind: ProjectionKind::Temporal,
                projected_by: FacultyKind::Planner,
                status: ProjectionStatus::Candidate,
                basis_refs: vec![candidate.handle.clone()],
                candidate_refs: vec![sid("state:durable-admission/next")],
                constraint_refs: vec!["persist before publish".to_owned()],
                residuals: Vec::new(),
            },
        ],
        activations,
        returns,
        omissions: Vec::new(),
        observer_disposition: ObserverDisposition::Admit,
        after_state_ref: candidate.handle.clone(),
        residuals: Vec::new(),
    }
}

fn arguments(request: AccountingHostRequest) -> serde_json::Map<String, Value> {
    json!({ "request": request }).as_object().unwrap().clone()
}

fn response(result: &rmcp::model::CallToolResult) -> IdentityAccountingMcpResponse {
    serde_json::from_value(result.structured_content.clone().unwrap()).unwrap()
}

#[tokio::test]
async fn admitted_identity_persists_restarts_and_resolves_through_the_existing_tool() {
    let directory = TempDirectory::new();
    let base = new_identity_ledger(
        sid("basket:durable-admission"),
        vec![object("alpha", "source:alpha")],
    )
    .unwrap();
    let journal = new_accounting_journal(sid("journal:durable-admission"), base.clone()).unwrap();
    let config = SnapshotStoreConfig {
        directory: directory.0.clone(),
        journal_id: journal.journal_id.clone(),
        maximum_snapshot_bytes: 4 * 1024 * 1024,
        maximum_snapshots: 32,
    };
    SnapshotStore::initialize(config.clone(), &journal).unwrap();
    let candidate = object("beta", "source:beta");
    let admission = finalize_accountable_object_admission(AccountableObjectAdmission {
        profile: ACCOUNTABLE_OBJECT_ADMISSION_PROFILE.to_owned(),
        admission_id: sid("admission:durable/beta"),
        expected_ledger_digest: base.ledger_digest.clone(),
        evidence_refs: candidate.provenance_refs.clone(),
        faculty_cycle: faculty_cycle(&base, &candidate),
        candidate: candidate.clone(),
        admission_digest: empty_digest(),
    })
    .unwrap();
    let server = IdentityAccountingMcpServer::open(config.clone()).unwrap();
    let admitted = server
        .execute_tool_arguments(Some(arguments(AccountingHostRequest {
            profile: ACCOUNTING_HOST_REQUEST_PROFILE.to_owned(),
            request_id: sid("request:durable-admit/beta"),
            expected_journal_digest: journal.journal_digest.clone(),
            operation: AccountingHostOperation::AdmitObject {
                admission: Box::new(admission),
            },
        })))
        .await;
    assert_eq!(response(&admitted).status, AccountingMcpStatus::Succeeded);
    let persisted = server.snapshot().await;
    assert_eq!(persisted.events.len(), 2);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    drop(server);

    let restarted = IdentityAccountingMcpServer::open(config).unwrap();
    let restored = restarted.snapshot().await;
    assert_eq!(restored, persisted);
    let resolved = restarted
        .execute_tool_arguments(Some(arguments(AccountingHostRequest {
            profile: ACCOUNTING_HOST_REQUEST_PROFILE.to_owned(),
            request_id: sid("request:resolve-admitted/beta"),
            expected_journal_digest: restored.journal_digest.clone(),
            operation: AccountingHostOperation::Resolve {
                query: candidate.handle.to_string(),
            },
        })))
        .await;
    let resolved = response(&resolved);
    assert_eq!(resolved.status, AccountingMcpStatus::Succeeded);
    assert!(matches!(
        resolved.result.unwrap().result,
        AccountingHostResult::Resolution {
            resolution: ReferenceResolution::Resolved { handle }
        } if handle == candidate.handle
    ));
}
