use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ACCOUNTABLE_OBJECT_PROFILE, AccountableObject, AccountableObjectPatch, AttentionCapacity,
    AttentionMemberDisposition, AttentionMemberReceipt, AttentionParticipant, AttentionReceiptSeed,
    AttentionReceiptStatus, EpistemicStatus, FacultyKind, FramedProposition, ReferenceResolution,
    SemanticId, SharedAttentionFaultCode, SharedAttentionFrame, SharedAttentionFrameSeed,
    apply_accountable_object_patch, compile_accountability_window, finalize_accountable_object,
    finalize_attention_receipt, inspect_accountable_object, new_identity_ledger,
    new_shared_attention_frame, resolve_accountability_reference, validate_accountability_window,
    validate_identity_ledger,
};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture semantic identity")
}

fn empty_digest() -> cantor_core::ContentDigest {
    cantor_core::ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn frame() -> SharedAttentionFrame {
    let participant = AttentionParticipant {
        participant_id: sid("participant:accounting-guard"),
        faculties: BTreeSet::from([
            FacultyKind::Observer,
            FacultyKind::Honesty,
            FacultyKind::Security,
        ]),
        required: true,
    };
    let proposition = FramedProposition {
        proposition_id: sid("proposition:account-for-flight"),
        text: "Account for every aircraft before proposing dispatch.".to_owned(),
        epistemic_status: EpistemicStatus::Observed,
        source_refs: BTreeSet::from([sid("source:accounting-fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: None,
    };
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:accounting-fixture"),
        purpose: "select a ready transport without identity loss".to_owned(),
        policy_ref: sid("policy:identity-accounting-p0"),
        participants: BTreeMap::from([(participant.participant_id.clone(), participant)]),
        propositions: BTreeMap::from([(proposition.proposition_id.clone(), proposition)]),
        constraints: BTreeMap::from([(
            sid("constraint:complete-roster"),
            "every basket member receives a disposition".to_owned(),
        )]),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::from([sid("proposition:account-for-flight")]),
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
    .expect("valid accounting frame")
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
    .expect("valid accountable aircraft")
}

fn ledger() -> cantor_core::IdentityLedger {
    new_identity_ledger(
        sid("basket:flight-group-7"),
        vec![
            aircraft("001", &["lead", "shared-call-sign"], "ready"),
            aircraft("002", &["reserve", "shared-call-sign"], "maintenance"),
            aircraft("003", &["trainer"], "ready"),
        ],
    )
    .expect("valid identity ledger")
}

#[test]
fn complete_register_keeps_same_type_members_distinct_and_ordered() {
    let ledger = ledger();
    let window =
        compile_accountability_window(&frame(), &ledger, 100_000).expect("complete register fits");

    assert_eq!(window.register.member_count, 3);
    assert_eq!(
        window
            .register
            .entries
            .iter()
            .map(|entry| entry.handle.as_str())
            .collect::<Vec<_>>(),
        vec![
            "object:aircraft/001",
            "object:aircraft/002",
            "object:aircraft/003"
        ]
    );
    assert!(window.rendered_register.contains("@object:aircraft/001"));
    assert!(window.rendered_register.contains("@object:aircraft/002"));
    assert!(window.rendered_register.contains("@object:aircraft/003"));
    assert_eq!(window.ledger_digest, ledger.ledger_digest);
    assert_eq!(
        window,
        compile_accountability_window(&frame(), &ledger, 100_000)
            .expect("equal input projects byte-equivalent window")
    );
}

#[test]
fn resolver_prefers_exact_handles_and_refuses_ambiguous_or_unknown_labels() {
    let ledger = ledger();
    assert_eq!(
        resolve_accountability_reference(&ledger, "@object:aircraft/002").unwrap(),
        ReferenceResolution::Resolved {
            handle: sid("object:aircraft/002")
        }
    );
    assert_eq!(
        resolve_accountability_reference(&ledger, " RESERVE ").unwrap(),
        ReferenceResolution::Resolved {
            handle: sid("object:aircraft/002")
        }
    );
    assert_eq!(
        resolve_accountability_reference(&ledger, "shared-call-sign").unwrap(),
        ReferenceResolution::Ambiguous {
            candidates: BTreeSet::from([sid("object:aircraft/001"), sid("object:aircraft/002")])
        }
    );
    assert_eq!(
        resolve_accountability_reference(&ledger, "missing").unwrap(),
        ReferenceResolution::Unknown {
            query: "missing".to_owned()
        }
    );
}

#[test]
fn compare_and_set_patch_changes_one_object_and_conserves_membership() {
    let ledger = ledger();
    let before_001 = ledger.objects[&sid("object:aircraft/001")].clone();
    let before_003 = ledger.objects[&sid("object:aircraft/003")].clone();
    let patch = AccountableObjectPatch {
        expected_ledger_digest: ledger.ledger_digest.clone(),
        handle: sid("object:aircraft/002"),
        expected_version: 1,
        labels: None,
        differentiators: None,
        state: Some(BTreeMap::from([(
            "readiness".to_owned(),
            "ready".to_owned(),
        )])),
        roles: None,
        purposes: None,
        obligations: None,
        provenance_refs: Some(BTreeSet::from([
            sid("source:aircraft-002"),
            sid("evidence:maintenance-release"),
        ])),
    };

    let successor = apply_accountable_object_patch(&ledger, patch.clone()).unwrap();
    assert_eq!(successor.objects.len(), ledger.objects.len());
    assert_eq!(successor.objects[&sid("object:aircraft/001")], before_001);
    assert_eq!(successor.objects[&sid("object:aircraft/003")], before_003);
    let changed = &successor.objects[&sid("object:aircraft/002")];
    assert_eq!(changed.handle, sid("object:aircraft/002"));
    assert_eq!(changed.object_type, sid("aircraft"));
    assert_eq!(changed.version, 2);
    assert_eq!(changed.state["readiness"], "ready");
    assert_eq!(successor.generation, 2);
    validate_identity_ledger(&successor).unwrap();

    let mut stale_version = patch.clone();
    stale_version.expected_ledger_digest = successor.ledger_digest.clone();
    let fault = apply_accountable_object_patch(&successor, stale_version).unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::StaleBase);

    let fault = apply_accountable_object_patch(&successor, patch).unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::StaleLedger);
}

#[test]
fn complete_register_refuses_capacity_pressure_instead_of_truncating() {
    let ledger = ledger();
    let complete = compile_accountability_window(&frame(), &ledger, 100_000).unwrap();
    let required = complete.rendered_register.len() as u64;
    let fault = compile_accountability_window(&frame(), &ledger, required - 1).unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::CapacityOverflow);
    assert!(fault.message.contains("refusing truncation"));
}

fn member_receipt(handle: &str, disposition: AttentionMemberDisposition) -> AttentionMemberReceipt {
    AttentionMemberReceipt {
        handle: sid(handle),
        disposition,
        rationale: format!("{handle} received an explicit fixture disposition"),
        evidence_refs: BTreeSet::new(),
    }
}

#[test]
fn attention_receipt_requires_exact_full_coverage_and_holds_unresolved_members() {
    let ledger = ledger();
    let window = compile_accountability_window(&frame(), &ledger, 100_000).unwrap();
    let incomplete = AttentionReceiptSeed {
        receipt_id: sid("receipt:incomplete"),
        window_digest: window.window_digest.clone(),
        ledger_digest: window.ledger_digest.clone(),
        register_digest: window.register.register_digest.clone(),
        member_receipts: BTreeMap::from([
            (
                sid("object:aircraft/001"),
                member_receipt("object:aircraft/001", AttentionMemberDisposition::Relevant),
            ),
            (
                sid("object:aircraft/002"),
                member_receipt("object:aircraft/002", AttentionMemberDisposition::Relevant),
            ),
        ]),
    };
    let fault = finalize_attention_receipt(&window, incomplete).unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::MissingAttestation);

    let complete_members = BTreeMap::from([
        (
            sid("object:aircraft/001"),
            member_receipt("object:aircraft/001", AttentionMemberDisposition::Relevant),
        ),
        (
            sid("object:aircraft/002"),
            member_receipt(
                "object:aircraft/002",
                AttentionMemberDisposition::NotApplicable,
            ),
        ),
        (
            sid("object:aircraft/003"),
            member_receipt(
                "object:aircraft/003",
                AttentionMemberDisposition::NotApplicable,
            ),
        ),
    ]);
    let receipt = finalize_attention_receipt(
        &window,
        AttentionReceiptSeed {
            receipt_id: sid("receipt:complete"),
            window_digest: window.window_digest.clone(),
            ledger_digest: window.ledger_digest.clone(),
            register_digest: window.register.register_digest.clone(),
            member_receipts: complete_members.clone(),
        },
    )
    .unwrap();
    assert_eq!(receipt.status, AttentionReceiptStatus::Complete);

    let mut held_members = complete_members;
    held_members.insert(
        sid("object:aircraft/002"),
        member_receipt(
            "object:aircraft/002",
            AttentionMemberDisposition::Unresolved,
        ),
    );
    let held = finalize_attention_receipt(
        &window,
        AttentionReceiptSeed {
            receipt_id: sid("receipt:held"),
            window_digest: window.window_digest.clone(),
            ledger_digest: window.ledger_digest.clone(),
            register_digest: window.register.register_digest.clone(),
            member_receipts: held_members,
        },
    )
    .unwrap();
    assert_eq!(held.status, AttentionReceiptStatus::Held);
}

#[test]
fn exact_inspection_tamper_detection_and_strict_machine_forms_fail_closed() {
    let ledger = ledger();
    assert_eq!(
        inspect_accountable_object(&ledger, &sid("object:aircraft/003"))
            .unwrap()
            .labels,
        BTreeSet::from(["trainer".to_owned()])
    );
    let fault = inspect_accountable_object(&ledger, &sid("object:aircraft/999")).unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::UnknownReference);

    let mut tampered_ledger = ledger.clone();
    tampered_ledger
        .objects
        .get_mut(&sid("object:aircraft/001"))
        .unwrap()
        .state
        .insert("readiness".to_owned(), "invented".to_owned());
    assert_eq!(
        validate_identity_ledger(&tampered_ledger).unwrap_err().code,
        SharedAttentionFaultCode::InvalidDigest
    );

    let mut window = compile_accountability_window(&frame(), &ledger, 100_000).unwrap();
    window.rendered_register.push_str("\nINVENTED MEMBER");
    assert_eq!(
        validate_accountability_window(&window).unwrap_err().code,
        SharedAttentionFaultCode::InvalidFrame
    );

    let mut value = serde_json::to_value(AccountableObjectPatch {
        expected_ledger_digest: ledger.ledger_digest,
        handle: sid("object:aircraft/001"),
        expected_version: 1,
        labels: None,
        differentiators: None,
        state: None,
        roles: None,
        purposes: None,
        obligations: None,
        provenance_refs: None,
    })
    .unwrap();
    value["invented_authority"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<AccountableObjectPatch>(value).is_err());
}

#[test]
fn malformed_typed_handle_and_duplicate_identity_are_rejected() {
    let mut malformed = aircraft("001", &["lead"], "ready");
    malformed.handle = sid("object:vehicle/001");
    malformed.record_digest = empty_digest();
    let fault = finalize_accountable_object(malformed).unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::InvalidLedger);

    let duplicate = aircraft("001", &["lead"], "ready");
    let fault = new_identity_ledger(sid("basket:duplicate"), vec![duplicate.clone(), duplicate])
        .unwrap_err();
    assert_eq!(fault.code, SharedAttentionFaultCode::DuplicateIdentity);
}
