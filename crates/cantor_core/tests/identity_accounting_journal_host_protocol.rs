use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ACCOUNTABLE_OBJECT_PROFILE, ACCOUNTING_HOST_REQUEST_PROFILE, AccountableObject,
    AccountableObjectPatch, AccountingHostOperation, AccountingHostRequest, AccountingHostResult,
    AttentionCapacity, AttentionParticipant, ContentDigest, EpistemicStatus, FacultyKind,
    FramedProposition, ReferenceResolution, SemanticId, SharedAttentionFaultCode,
    SharedAttentionFrame, SharedAttentionFrameSeed, decode_accounting_journal,
    encode_accounting_journal, execute_accounting_host_request, finalize_accountable_object,
    new_accounting_journal, new_identity_ledger, new_shared_attention_frame, sha256_digest,
    validate_accounting_host_response, validate_accounting_journal,
};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture semantic identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn aircraft(local_id: &str, labels: &[&str], readiness: &str) -> AccountableObject {
    finalize_accountable_object(AccountableObject {
        profile: ACCOUNTABLE_OBJECT_PROFILE.to_owned(),
        handle: sid(&format!("object:aircraft/{local_id}")),
        object_type: sid("aircraft"),
        labels: labels.iter().map(|label| (*label).to_owned()).collect(),
        differentiators: BTreeMap::from([("tail".to_owned(), local_id.to_owned())]),
        state: BTreeMap::from([("readiness".to_owned(), readiness.to_owned())]),
        roles: BTreeSet::from([sid("role:transport")]),
        purposes: BTreeSet::from([sid("purpose:dispatch")]),
        obligations: BTreeSet::from([sid("obligation:account-before-dispatch")]),
        provenance_refs: BTreeSet::from([sid(&format!("source:aircraft-{local_id}"))]),
        version: 1,
        record_digest: empty_digest(),
    })
    .expect("valid aircraft")
}

fn identity_ledger() -> cantor_core::IdentityLedger {
    new_identity_ledger(
        sid("basket:host-flight-group"),
        vec![
            aircraft("001", &["lead", "shared"], "ready"),
            aircraft("002", &["reserve", "shared"], "maintenance"),
            aircraft("003", &["trainer"], "ready"),
        ],
    )
    .expect("valid identity ledger")
}

fn journal() -> cantor_core::AccountingJournal {
    new_accounting_journal(sid("journal:host-flight-group"), identity_ledger())
        .expect("valid accounting journal")
}

fn frame() -> SharedAttentionFrame {
    let participant = AttentionParticipant {
        participant_id: sid("participant:accounting-host-guard"),
        faculties: BTreeSet::from([
            FacultyKind::Observer,
            FacultyKind::Honesty,
            FacultyKind::Security,
        ]),
        required: true,
    };
    let proposition = FramedProposition {
        proposition_id: sid("proposition:select-aircraft"),
        text: "Select one aircraft without losing the others.".to_owned(),
        epistemic_status: EpistemicStatus::Observed,
        source_refs: BTreeSet::from([sid("source:host-protocol-fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: None,
    };
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:accounting-host"),
        purpose: "query an exact accountable basket".to_owned(),
        policy_ref: sid("policy:accounting-host-p1"),
        participants: BTreeMap::from([(participant.participant_id.clone(), participant)]),
        propositions: BTreeMap::from([(proposition.proposition_id.clone(), proposition)]),
        constraints: BTreeMap::new(),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::from([sid("proposition:select-aircraft")]),
        capacity: AttentionCapacity {
            accounting_profile: cantor_core::ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
            context_budget_bytes: 100_000,
            pinned_anchor_bytes: 0,
            current_focus_bytes: 100,
            retrieved_association_bytes: 0,
            recent_stream_bytes: 0,
            reserved_headroom_bytes: 1_000,
        },
    })
    .expect("valid frame")
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
    let ledger = journal
        .ledgers
        .get(&journal.head_ledger_digest.value)
        .expect("head ledger");
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

fn rehash_journal(journal: &mut cantor_core::AccountingJournal) {
    journal.journal_digest = empty_digest();
    journal.journal_digest = sha256_digest(journal).expect("fixture journal rehash");
}

#[test]
fn genesis_is_deterministic_replayable_and_canonically_restorable() {
    let first = journal();
    let second = journal();
    assert_eq!(first, second);
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.ledgers.len(), 1);
    validate_accounting_journal(&first).expect("valid genesis journal");

    let bytes = encode_accounting_journal(&first).expect("canonical bytes");
    assert_eq!(
        decode_accounting_journal(&bytes, bytes.len() as u64).unwrap(),
        first
    );
    assert_eq!(encode_accounting_journal(&second).unwrap(), bytes);
}

#[test]
fn read_protocol_projects_resolves_and_inspects_without_a_successor() {
    let journal = journal();
    let projected = execute_accounting_host_request(
        &journal,
        request(
            &journal,
            "request:project",
            AccountingHostOperation::Project {
                frame: Box::new(frame()),
                byte_budget: 100_000,
            },
        ),
    )
    .expect("project response");
    assert!(projected.successor.is_none());
    let AccountingHostResult::Window { window } = projected.response.result else {
        panic!("expected window")
    };
    assert_eq!(window.register.member_count, 3);

    for (id, query, expected) in [
        (
            "request:resolve-exact",
            "reserve",
            ReferenceResolution::Resolved {
                handle: sid("object:aircraft/002"),
            },
        ),
        (
            "request:resolve-ambiguous",
            "shared",
            ReferenceResolution::Ambiguous {
                candidates: BTreeSet::from([
                    sid("object:aircraft/001"),
                    sid("object:aircraft/002"),
                ]),
            },
        ),
        (
            "request:resolve-unknown",
            "absent",
            ReferenceResolution::Unknown {
                query: "absent".to_owned(),
            },
        ),
    ] {
        let transition = execute_accounting_host_request(
            &journal,
            request(
                &journal,
                id,
                AccountingHostOperation::Resolve {
                    query: query.to_owned(),
                },
            ),
        )
        .unwrap();
        assert!(transition.successor.is_none());
        assert_eq!(
            transition.response.result,
            AccountingHostResult::Resolution {
                resolution: expected
            }
        );
    }

    let inspected = execute_accounting_host_request(
        &journal,
        request(
            &journal,
            "request:inspect",
            AccountingHostOperation::InspectObject {
                handle: sid("object:aircraft/003"),
            },
        ),
    )
    .unwrap();
    assert!(inspected.successor.is_none());
    let AccountingHostResult::Object { object } = inspected.response.result else {
        panic!("expected object")
    };
    assert_eq!(object.handle, sid("object:aircraft/003"));
}

#[test]
fn patch_appends_one_semantically_replayable_generation_and_preserves_history() {
    let journal = journal();
    let patch_request = request(
        &journal,
        "request:release-reserve",
        AccountingHostOperation::ApplyPatch {
            patch: Box::new(patch(&journal, "ready")),
        },
    );
    let first = execute_accounting_host_request(&journal, patch_request.clone()).expect("patch");
    let replay =
        execute_accounting_host_request(&journal, patch_request).expect("deterministic patch");
    assert_eq!(first, replay);
    let successor = first.successor.expect("patch successor");
    assert_eq!(successor.events.len(), 2);
    assert_eq!(successor.ledgers.len(), 2);
    assert!(
        successor
            .ledgers
            .contains_key(&journal.head_ledger_digest.value)
    );
    validate_accounting_journal(&successor).expect("complete semantic replay");
    let head = &successor.ledgers[&successor.head_ledger_digest.value];
    assert_eq!(head.generation, 2);
    assert_eq!(
        head.objects[&sid("object:aircraft/002")].state["readiness"],
        "ready"
    );

    let stale = execute_accounting_host_request(
        &successor,
        request(
            &journal,
            "request:stale",
            AccountingHostOperation::InspectJournal,
        ),
    )
    .expect_err("old journal root must refuse");
    assert_eq!(stale.code, SharedAttentionFaultCode::StaleLedger);
}

#[test]
fn retained_ledger_and_event_reads_are_exact_and_inert() {
    let initial = journal();
    let applied = execute_accounting_host_request(
        &initial,
        request(
            &initial,
            "request:append",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(patch(&initial, "ready")),
            },
        ),
    )
    .unwrap()
    .successor
    .unwrap();
    let old = execute_accounting_host_request(
        &applied,
        request(
            &applied,
            "request:read-old-ledger",
            AccountingHostOperation::ReadLedger {
                ledger_digest: initial.head_ledger_digest.clone(),
            },
        ),
    )
    .unwrap();
    assert!(old.successor.is_none());
    let AccountingHostResult::Ledger { ledger } = old.response.result else {
        panic!("expected ledger")
    };
    assert_eq!(ledger.ledger_digest, initial.head_ledger_digest);

    let event_id = applied.events[0].event_id.clone();
    let event = execute_accounting_host_request(
        &applied,
        request(
            &applied,
            "request:read-event",
            AccountingHostOperation::ReadEvent {
                event_id: event_id.clone(),
            },
        ),
    )
    .unwrap();
    assert!(event.successor.is_none());
    let AccountingHostResult::Event { event } = event.response.result else {
        panic!("expected event")
    };
    assert_eq!(event.event_id, event_id);
}

#[test]
fn missing_snapshot_reorder_tamper_and_noncanonical_bytes_fail_closed() {
    let initial = journal();
    let mut applied = execute_accounting_host_request(
        &initial,
        request(
            &initial,
            "request:tamper-base",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(patch(&initial, "ready")),
            },
        ),
    )
    .unwrap()
    .successor
    .unwrap();

    applied.ledgers.remove(&initial.head_ledger_digest.value);
    rehash_journal(&mut applied);
    assert_eq!(
        validate_accounting_journal(&applied).unwrap_err().code,
        SharedAttentionFaultCode::InvalidLedger
    );

    let valid = journal();
    let bytes = encode_accounting_journal(&valid).unwrap();
    assert_eq!(
        decode_accounting_journal(&bytes, bytes.len() as u64 - 1)
            .unwrap_err()
            .code,
        SharedAttentionFaultCode::CapacityOverflow
    );
    let mut spaced = b" ".to_vec();
    spaced.extend_from_slice(&bytes);
    assert_eq!(
        decode_accounting_journal(&spaced, spaced.len() as u64)
            .unwrap_err()
            .code,
        SharedAttentionFaultCode::MachineForm
    );
    let mut value = serde_json::to_value(&valid).unwrap();
    value["invented_authority"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<cantor_core::AccountingJournal>(value).is_err());
}

#[test]
fn response_request_and_result_substitution_are_detected() {
    let journal = journal();
    let request = request(
        &journal,
        "request:summary",
        AccountingHostOperation::InspectJournal,
    );
    let transition = execute_accounting_host_request(&journal, request.clone()).unwrap();
    validate_accounting_host_response(&journal, &request, &transition.response).unwrap();

    let mut substituted = transition.response;
    substituted.request_id = sid("request:substituted");
    assert_eq!(
        validate_accounting_host_response(&journal, &request, &substituted)
            .unwrap_err()
            .code,
        SharedAttentionFaultCode::InvalidLedger
    );
}

#[test]
fn capacity_unknown_and_stale_object_boundaries_refuse_without_history() {
    let journal = journal();
    let capacity = execute_accounting_host_request(
        &journal,
        request(
            &journal,
            "request:too-small",
            AccountingHostOperation::Project {
                frame: Box::new(frame()),
                byte_budget: 1,
            },
        ),
    )
    .expect_err("complete roster must not truncate");
    assert_eq!(capacity.code, SharedAttentionFaultCode::CapacityOverflow);

    let unknown = execute_accounting_host_request(
        &journal,
        request(
            &journal,
            "request:unknown-event",
            AccountingHostOperation::ReadEvent {
                event_id: sid("accounting:event/absent"),
            },
        ),
    )
    .expect_err("unknown event");
    assert_eq!(unknown.code, SharedAttentionFaultCode::UnknownEvent);

    let mut stale_patch = patch(&journal, "ready");
    stale_patch.expected_version += 1;
    let stale = execute_accounting_host_request(
        &journal,
        request(
            &journal,
            "request:stale-object",
            AccountingHostOperation::ApplyPatch {
                patch: Box::new(stale_patch),
            },
        ),
    )
    .expect_err("stale object version");
    assert_eq!(stale.code, SharedAttentionFaultCode::StaleBase);
    assert_eq!(journal.events.len(), 1);
}
