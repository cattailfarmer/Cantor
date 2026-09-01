use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ACCOUNTABLE_OBJECT_ADMISSION_PROFILE, ACCOUNTABLE_OBJECT_PROFILE,
    ACCOUNTING_HOST_REQUEST_PROFILE, AccountableObject, AccountableObjectAdmission,
    AccountingHostOperation, AccountingHostRequest, AccountingHostResult,
    AccountingJournalMutation, CombinatoryProjection, ContentDigest, FacultyActivation,
    FacultyCycle, FacultyCycleKind, FacultyKind, FacultyLedger, FacultyReturn, FacultyReturnStatus,
    FacultyStage, IdentityBoundary, IdentityBoundaryDomain, IdentityLedger, ObserverDisposition,
    ProjectionKind, ProjectionStatus, SemanticId, SharedAttentionFaultCode,
    accounting_ledger_state_ref, admit_accountable_object, decode_accounting_journal,
    encode_accounting_journal, execute_accounting_host_request, finalize_accountable_object,
    finalize_accountable_object_admission, new_accounting_journal, new_identity_ledger,
    validate_accounting_journal,
};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).unwrap()
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn object(local: &str, source: &str, version: u64) -> AccountableObject {
    finalize_accountable_object(AccountableObject {
        profile: ACCOUNTABLE_OBJECT_PROFILE.to_owned(),
        handle: sid(&format!("object:airplane/{local}")),
        object_type: sid("airplane"),
        labels: BTreeSet::from([format!("airplane {local}")]),
        differentiators: BTreeMap::from([("tail_number".to_owned(), local.to_owned())]),
        state: BTreeMap::from([("readiness".to_owned(), "proposed".to_owned())]),
        roles: BTreeSet::from([sid("role:transport")]),
        purposes: BTreeSet::from([sid("purpose:identity-accounting")]),
        obligations: BTreeSet::from([sid("obligation:retain-distinction")]),
        provenance_refs: BTreeSet::from([sid(source)]),
        version,
        record_digest: empty_digest(),
    })
    .unwrap()
}

fn ledger() -> IdentityLedger {
    new_identity_ledger(
        sid("basket:judgment-gate"),
        vec![object("alpha", "source:alpha", 1)],
    )
    .unwrap()
}

fn activation(ordinal: u32, faculty: FacultyKind, stage: FacultyStage) -> FacultyActivation {
    FacultyActivation {
        activation_id: sid(&format!("activation:admission/{ordinal}")),
        faculty,
        stage,
        ordinal,
        purpose: format!("{faculty:?} performs {stage:?} for identity admission"),
        input_refs: vec![sid("proposal:airplane-beta")],
        unavailable_refs: Vec::new(),
    }
}

fn returned(activation: &FacultyActivation) -> FacultyReturn {
    FacultyReturn {
        activation_id: activation.activation_id.clone(),
        faculty: activation.faculty,
        status: FacultyReturnStatus::Accepted,
        output_refs: vec![sid(&format!("output:admission/{}", activation.ordinal))],
        objections: Vec::new(),
        uncertainty: Vec::new(),
        ledger: FacultyLedger {
            source_refs: vec!["source:beta".to_owned()],
            grounds: vec!["candidate and evidence remain exactly bound".to_owned()],
            constraint_refs: vec!["IAG-01..16".to_owned()],
            retained_boundaries: vec!["proposal is not membership".to_owned()],
            relation_refs: Vec::new(),
        },
    }
}

fn cycle(base: &IdentityLedger, candidate: &AccountableObject) -> FacultyCycle {
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
    let mut returns = activations.iter().map(returned).collect::<Vec<_>>();
    returns[2]
        .output_refs
        .push(sid("boundary:admission/epistemic"));
    returns[3]
        .output_refs
        .push(sid("boundary:admission/authority"));
    returns[4]
        .output_refs
        .push(sid("projection:admission/relational"));
    returns[5]
        .output_refs
        .push(sid("projection:admission/temporal"));
    let before = accounting_ledger_state_ref(&base.ledger_digest).unwrap();
    FacultyCycle {
        cycle_id: sid("cycle:identity-admission/beta"),
        kind: FacultyCycleKind::SemanticTransition,
        subject: candidate.handle.to_string(),
        purpose: "judge whether the exact candidate may join this identity basket".to_owned(),
        before_state_ref: before.clone(),
        identity_boundaries: vec![
            IdentityBoundary {
                boundary_id: sid("boundary:admission/epistemic"),
                domain: IdentityBoundaryDomain::Epistemic,
                guarded_by: FacultyKind::Honesty,
                subject_ref: candidate.handle.clone(),
                inside: vec!["declared evidence and candidate properties".to_owned()],
                edge_conditions: vec!["evidence or property identity changes".to_owned()],
                outside: vec!["external truth not established by this record".to_owned()],
                uncertainty: Vec::new(),
            },
            IdentityBoundary {
                boundary_id: sid("boundary:admission/authority"),
                domain: IdentityBoundaryDomain::Authority,
                guarded_by: FacultyKind::Security,
                subject_ref: candidate.handle.clone(),
                inside: vec!["in-memory basket membership proposal".to_owned()],
                edge_conditions: vec!["persistence or effect is requested".to_owned()],
                outside: vec!["journal MCP and external effects".to_owned()],
                uncertainty: Vec::new(),
            },
        ],
        projections: vec![
            CombinatoryProjection {
                projection_id: sid("projection:admission/relational"),
                kind: ProjectionKind::Relational,
                projected_by: FacultyKind::Weaver,
                status: ProjectionStatus::Candidate,
                basis_refs: vec![before],
                candidate_refs: vec![candidate.handle.clone()],
                constraint_refs: vec!["preserve all existing identities".to_owned()],
                residuals: Vec::new(),
            },
            CombinatoryProjection {
                projection_id: sid("projection:admission/temporal"),
                kind: ProjectionKind::Temporal,
                projected_by: FacultyKind::Planner,
                status: ProjectionStatus::Candidate,
                basis_refs: vec![candidate.handle.clone()],
                candidate_refs: vec![sid("state:admission/next-generation")],
                constraint_refs: vec!["insert exactly one generation".to_owned()],
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

fn admission(base: &IdentityLedger, candidate: AccountableObject) -> AccountableObjectAdmission {
    finalize_accountable_object_admission(AccountableObjectAdmission {
        profile: ACCOUNTABLE_OBJECT_ADMISSION_PROFILE.to_owned(),
        admission_id: sid("admission:airplane/beta"),
        expected_ledger_digest: base.ledger_digest.clone(),
        evidence_refs: candidate.provenance_refs.clone(),
        faculty_cycle: cycle(base, &candidate),
        candidate,
        admission_digest: empty_digest(),
    })
    .unwrap()
}

#[test]
fn unanimous_seven_faculty_judgment_admits_exactly_one_deterministic_successor() {
    let base = ledger();
    let proposal = admission(&base, object("beta", "source:beta", 1));
    let first = admit_accountable_object(&base, &proposal).unwrap();
    let second = admit_accountable_object(&base, &proposal).unwrap();

    assert_eq!(first, second);
    assert_eq!(base.generation, 1);
    assert_eq!(base.objects.len(), 1);
    assert_eq!(first.generation, 2);
    assert_eq!(first.objects.len(), 2);
    assert_eq!(
        first.objects[&proposal.candidate.handle],
        proposal.candidate
    );
}

#[test]
fn stale_base_and_duplicate_exact_identity_refuse_without_source_mutation() {
    let base = ledger();
    let proposal = admission(&base, object("beta", "source:beta", 1));
    let successor = admit_accountable_object(&base, &proposal).unwrap();
    let stale = admit_accountable_object(&successor, &proposal).unwrap_err();
    assert_eq!(stale.code, SharedAttentionFaultCode::StaleLedger);

    let duplicate = admission(&successor, proposal.candidate.clone());
    let duplicate_fault = admit_accountable_object(&successor, &duplicate).unwrap_err();
    assert_eq!(
        duplicate_fault.code,
        SharedAttentionFaultCode::DuplicateIdentity
    );
    assert_eq!(base.objects.len(), 1);
}

#[test]
fn non_admit_qualified_uncertain_or_residual_judgment_cannot_be_finalized() {
    let base = ledger();
    let candidate = object("beta", "source:beta", 1);
    let mut cases = Vec::new();

    let mut blocked = cycle(&base, &candidate);
    blocked.observer_disposition = ObserverDisposition::Block;
    cases.push(blocked);
    let mut qualified = cycle(&base, &candidate);
    qualified.returns[4].status = FacultyReturnStatus::Qualified;
    cases.push(qualified);
    let mut uncertain = cycle(&base, &candidate);
    uncertain.returns[4]
        .uncertainty
        .push("relation remains unresolved".to_owned());
    cases.push(uncertain);
    let mut residual = cycle(&base, &candidate);
    residual
        .residuals
        .push("candidate scope remains open".to_owned());
    cases.push(residual);

    for faculty_cycle in cases {
        let fault = finalize_accountable_object_admission(AccountableObjectAdmission {
            profile: ACCOUNTABLE_OBJECT_ADMISSION_PROFILE.to_owned(),
            admission_id: sid("admission:airplane/beta"),
            expected_ledger_digest: base.ledger_digest.clone(),
            evidence_refs: candidate.provenance_refs.clone(),
            candidate: candidate.clone(),
            faculty_cycle,
            admission_digest: empty_digest(),
        })
        .unwrap_err();
        assert_eq!(fault.code, SharedAttentionFaultCode::UnresolvedChallenge);
    }
}

#[test]
fn invalid_cycle_evidence_version_and_state_bindings_fail_closed() {
    let base = ledger();
    let candidate = object("beta", "source:beta", 1);

    let mut invalid_cycle = cycle(&base, &candidate);
    invalid_cycle.returns.pop();
    let mut evidence_mismatch = candidate.provenance_refs.clone();
    evidence_mismatch.insert(sid("source:unbound"));
    let mut bad_binding = cycle(&base, &candidate);
    bad_binding.after_state_ref = sid("object:airplane/gamma");

    for (candidate_case, evidence, faculty_cycle, expected) in [
        (
            candidate.clone(),
            candidate.provenance_refs.clone(),
            invalid_cycle,
            SharedAttentionFaultCode::InvalidTransition,
        ),
        (
            candidate.clone(),
            evidence_mismatch,
            cycle(&base, &candidate),
            SharedAttentionFaultCode::EpistemicBoundary,
        ),
        (
            object("beta", "source:beta", 2),
            candidate.provenance_refs.clone(),
            cycle(&base, &candidate),
            SharedAttentionFaultCode::InvalidTransition,
        ),
        (
            candidate.clone(),
            candidate.provenance_refs.clone(),
            bad_binding,
            SharedAttentionFaultCode::InvalidTransition,
        ),
    ] {
        let fault = finalize_accountable_object_admission(AccountableObjectAdmission {
            profile: ACCOUNTABLE_OBJECT_ADMISSION_PROFILE.to_owned(),
            admission_id: sid("admission:airplane/beta"),
            expected_ledger_digest: base.ledger_digest.clone(),
            candidate: candidate_case,
            evidence_refs: evidence,
            faculty_cycle,
            admission_digest: empty_digest(),
        })
        .unwrap_err();
        assert_eq!(fault.code, expected);
    }
}

#[test]
fn admission_identity_substitution_is_detected_by_its_canonical_digest() {
    let base = ledger();
    let mut proposal = admission(&base, object("beta", "source:beta", 1));
    proposal.admission_id = sid("admission:airplane/substituted");
    let fault = admit_accountable_object(&base, &proposal).unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::InvalidDigest);
}

#[test]
fn admission_operation_appends_replays_restores_and_detects_event_tamper() {
    let base = ledger();
    let proposal = admission(&base, object("beta", "source:beta", 1));
    let journal = new_accounting_journal(sid("journal:judgment-gate"), base).unwrap();
    let request = AccountingHostRequest {
        profile: ACCOUNTING_HOST_REQUEST_PROFILE.to_owned(),
        request_id: sid("request:admit/beta"),
        expected_journal_digest: journal.journal_digest.clone(),
        operation: AccountingHostOperation::AdmitObject {
            admission: Box::new(proposal.clone()),
        },
    };
    let transition = execute_accounting_host_request(&journal, request).unwrap();
    let successor = transition.successor.unwrap();
    validate_accounting_journal(&successor).unwrap();
    assert_eq!(successor.events.len(), 2);
    assert_eq!(successor.ledgers.len(), 2);
    assert_eq!(
        successor.events[1].touched_handle,
        Some(proposal.candidate.handle.clone())
    );
    assert_eq!(
        successor.events[1].mutation,
        AccountingJournalMutation::AdmissionApplied {
            admission: Box::new(proposal.clone())
        }
    );
    assert!(matches!(
        transition.response.result,
        AccountingHostResult::Applied { .. }
    ));

    let bytes = encode_accounting_journal(&successor).unwrap();
    assert_eq!(
        decode_accounting_journal(&bytes, bytes.len() as u64).unwrap(),
        successor
    );

    let mut tampered = successor;
    let AccountingJournalMutation::AdmissionApplied { admission } =
        &mut tampered.events[1].mutation
    else {
        panic!("second event must be admission");
    };
    admission.admission_id = sid("admission:airplane/substituted");
    assert!(validate_accounting_journal(&tampered).is_err());
}
