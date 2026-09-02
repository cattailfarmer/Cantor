use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ACCOUNTABLE_OBJECT_PROFILE, ACCOUNTING_HOST_REQUEST_PROFILE, AccountableObject,
    AccountableObjectPatch, AccountingHostOperation, AccountingHostRequest, AccountingHostResult,
    AttentionCapacity, AttentionMemberDisposition, AttentionMemberReceipt, AttentionParticipant,
    ContentDigest, EpistemicStatus, FacultyKind, FramedProposition,
    ManifestAttentionReceiptSeed, SemanticId, SharedAttentionFaultCode, SharedAttentionFrame,
    SharedAttentionFrameSeed, apply_accountable_object_patch,
    compile_accountability_manifest_window, compile_accountability_window,
    execute_accounting_host_request,
    finalize_accountable_object, finalize_manifest_attention_receipt,
    materialize_accountable_objects, new_accounting_journal, new_identity_ledger,
    new_shared_attention_frame, validate_manifest_attention_receipt,
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

fn object(id: &str, labels: &[&str], state: &str) -> AccountableObject {
    finalize_accountable_object(AccountableObject {
        profile: ACCOUNTABLE_OBJECT_PROFILE.to_owned(),
        handle: sid(&format!("object:aircraft/{id}")),
        object_type: sid("aircraft"),
        labels: labels.iter().map(|value| (*value).to_owned()).collect(),
        differentiators: BTreeMap::from([("tail".to_owned(), id.to_owned())]),
        state: BTreeMap::from([("readiness".to_owned(), state.to_owned())]),
        roles: BTreeSet::from([sid("role:transport")]),
        purposes: BTreeSet::from([sid("purpose:dispatch")]),
        obligations: BTreeSet::new(),
        provenance_refs: BTreeSet::from([sid("source:manifest-fixture")]),
        version: 1,
        record_digest: empty_digest(),
    })
    .expect("valid accountable object")
}

fn ledger() -> cantor_core::IdentityLedger {
    new_identity_ledger(
        sid("basket:manifest-flight"),
        vec![
            object("001", &["shared"], "ready"),
            object("002", &["shared"], "maintenance"),
            object("003", &[], "ready"),
        ],
    )
    .expect("valid ledger")
}

fn frame() -> SharedAttentionFrame {
    let participant = AttentionParticipant {
        participant_id: sid("participant:manifest-observer"),
        faculties: BTreeSet::from([
            FacultyKind::Observer,
            FacultyKind::Honesty,
            FacultyKind::Security,
        ]),
        required: true,
    };
    let proposition = FramedProposition {
        proposition_id: sid("proposition:manifest-accounting"),
        text: "Account for every aircraft before selecting relevant records.".to_owned(),
        epistemic_status: EpistemicStatus::Observed,
        source_refs: BTreeSet::from([sid("source:manifest-fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: None,
    };
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:manifest-accounting"),
        purpose: "retain complete identity while selectively materializing bodies".to_owned(),
        policy_ref: sid("policy:manifest-refresh-p6"),
        participants: BTreeMap::from([(participant.participant_id.clone(), participant)]),
        propositions: BTreeMap::from([(proposition.proposition_id.clone(), proposition)]),
        constraints: BTreeMap::new(),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::from([sid("proposition:manifest-accounting")]),
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

fn receipt_member(handle: &str, disposition: AttentionMemberDisposition) -> AttentionMemberReceipt {
    AttentionMemberReceipt {
        handle: sid(handle),
        disposition,
        rationale: "explicit fixture disposition".to_owned(),
        evidence_refs: BTreeSet::from([sid("evidence:unverified-fixture-reference")]),
    }
}

#[test]
fn compact_manifest_is_complete_deterministic_and_refuses_one_byte_low_budget() {
    let ledger = ledger();
    let window = compile_accountability_manifest_window(&frame(), &ledger, 100_000).unwrap();
    assert_eq!(window.manifest.member_count, 3);
    assert_eq!(
        window
            .manifest
            .entries
            .iter()
            .map(|entry| (entry.handle.as_str(), entry.display_label.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("object:aircraft/001", "shared"),
            ("object:aircraft/002", "shared"),
            ("object:aircraft/003", "@object:aircraft/003"),
        ]
    );
    assert_eq!(
        window,
        compile_accountability_manifest_window(&frame(), &ledger, 100_000).unwrap()
    );
    let exact = window.rendered_manifest.len() as u64;
    assert!(compile_accountability_manifest_window(&frame(), &ledger, exact).is_ok());
    assert_eq!(
        compile_accountability_manifest_window(&frame(), &ledger, exact - 1)
            .unwrap_err()
            .code,
        SharedAttentionFaultCode::CapacityOverflow
    );
}

#[test]
fn compact_manifest_excludes_mutable_bodies_and_is_smaller_than_full_register() {
    let ledger = ledger();
    let manifest = compile_accountability_manifest_window(&frame(), &ledger, 100_000).unwrap();
    let full = compile_accountability_window(&frame(), &ledger, 100_000).unwrap();
    assert_eq!(manifest.manifest.member_count, full.register.member_count);
    assert!(manifest.rendered_manifest.len() < full.rendered_register.len());
    assert!(!manifest.rendered_manifest.contains("readiness"));
    assert!(!manifest.rendered_manifest.contains("maintenance"));
    assert!(!manifest.rendered_manifest.contains("differentiators"));
    eprintln!(
        "manifest_bytes={} full_register_bytes={} reduction_bytes={}",
        manifest.rendered_manifest.len(),
        full.rendered_register.len(),
        full.rendered_register.len() - manifest.rendered_manifest.len()
    );
}

#[test]
fn manifest_savings_scale_with_body_richness_without_losing_membership() {
    let mut prior_reduction = 0usize;
    for (member_count, payload_bytes) in [(1usize, 64usize), (8, 256), (32, 1_024)] {
        let objects = (0..member_count)
            .map(|index| {
                let id = format!("{index:03}");
                let mut candidate = object(&id, &["shared-type"], "ready");
                candidate.state.insert(
                    "body-payload".to_owned(),
                    "x".repeat(payload_bytes),
                );
                finalize_accountable_object(candidate).unwrap()
            })
            .collect();
        let ledger = new_identity_ledger(sid("basket:manifest-scaling"), objects).unwrap();
        let manifest =
            compile_accountability_manifest_window(&frame(), &ledger, 1_000_000).unwrap();
        let full = compile_accountability_window(&frame(), &ledger, 1_000_000).unwrap();
        let reduction = full.rendered_register.len() - manifest.rendered_manifest.len();
        assert_eq!(manifest.manifest.member_count, member_count as u64);
        assert_eq!(manifest.manifest.member_count, full.register.member_count);
        assert!(reduction > prior_reduction);
        prior_reduction = reduction;
        eprintln!(
            "members={member_count} payload_bytes={payload_bytes} manifest_bytes={} full_register_bytes={} reduction_bytes={reduction}",
            manifest.rendered_manifest.len(),
            full.rendered_register.len(),
        );
    }
}

#[test]
fn exact_materialization_canonicalizes_selection_and_refuses_duplicates_or_unknowns() {
    let ledger = ledger();
    let window = compile_accountability_manifest_window(&frame(), &ledger, 100_000).unwrap();
    let result = materialize_accountable_objects(
        &window,
        &ledger,
        vec![sid("object:aircraft/003"), sid("object:aircraft/001")],
    )
    .unwrap();
    assert_eq!(
        result
            .requested_handles
            .iter()
            .map(SemanticId::as_str)
            .collect::<Vec<_>>(),
        vec!["object:aircraft/001", "object:aircraft/003"]
    );
    assert_eq!(
        result
            .objects
            .iter()
            .map(|object| object.handle.as_str())
            .collect::<Vec<_>>(),
        vec!["object:aircraft/001", "object:aircraft/003"]
    );
    assert_eq!(
        materialize_accountable_objects(
            &window,
            &ledger,
            vec![sid("object:aircraft/001"), sid("object:aircraft/001")],
        )
        .unwrap_err()
        .code,
        SharedAttentionFaultCode::DuplicateIdentity
    );
    assert_eq!(
        materialize_accountable_objects(
            &window,
            &ledger,
            vec![sid("object:aircraft/404")],
        )
        .unwrap_err()
        .code,
        SharedAttentionFaultCode::UnknownReference
    );
    assert_eq!(
        materialize_accountable_objects(
            &window,
            &ledger,
            (0..=cantor_core::MAX_MATERIALIZED_HANDLES)
                .map(|index| sid(&format!("object:aircraft/{index:03}")))
                .collect(),
        )
        .unwrap_err()
        .code,
        SharedAttentionFaultCode::CapacityOverflow
    );
}

#[test]
fn receipt_requires_full_coverage_and_materialization_for_relevant_members() {
    let ledger = ledger();
    let window = compile_accountability_manifest_window(&frame(), &ledger, 100_000).unwrap();
    let materialization = materialize_accountable_objects(
        &window,
        &ledger,
        vec![sid("object:aircraft/001")],
    )
    .unwrap();
    let members = BTreeMap::from([
        (
            sid("object:aircraft/001"),
            receipt_member("object:aircraft/001", AttentionMemberDisposition::Relevant),
        ),
        (
            sid("object:aircraft/002"),
            receipt_member(
                "object:aircraft/002",
                AttentionMemberDisposition::NotApplicable,
            ),
        ),
        (
            sid("object:aircraft/003"),
            receipt_member("object:aircraft/003", AttentionMemberDisposition::Unresolved),
        ),
    ]);
    let seed = ManifestAttentionReceiptSeed {
        receipt_id: sid("receipt:manifest-held"),
        window_digest: window.window_digest.clone(),
        ledger_digest: ledger.ledger_digest.clone(),
        manifest_digest: window.manifest.manifest_digest.clone(),
        materialization_digest: materialization.materialization_digest.clone(),
        member_receipts: members,
    };
    let receipt = finalize_manifest_attention_receipt(&window, &ledger, &materialization, seed)
        .expect("full coverage held receipt");
    assert_eq!(receipt.status, cantor_core::AttentionReceiptStatus::Held);
    assert_eq!(
        receipt.member_receipts[&sid("object:aircraft/001")].evidence_refs,
        BTreeSet::from([sid("evidence:unverified-fixture-reference")])
    );
    validate_manifest_attention_receipt(&window, &ledger, &materialization, &receipt).unwrap();

    let mut missing = receipt.clone();
    missing.member_receipts.remove(&sid("object:aircraft/003"));
    assert_eq!(
        validate_manifest_attention_receipt(&window, &ledger, &materialization, &missing)
            .unwrap_err()
            .code,
        SharedAttentionFaultCode::MissingAttestation
    );
    let mut unmaterialized = receipt.clone();
    unmaterialized
        .member_receipts
        .get_mut(&sid("object:aircraft/002"))
        .unwrap()
        .disposition = AttentionMemberDisposition::Relevant;
    assert_eq!(
        validate_manifest_attention_receipt(&window, &ledger, &materialization, &unmaterialized)
            .unwrap_err()
            .code,
        SharedAttentionFaultCode::MissingAttestation
    );
    let mut empty_rationale = receipt.clone();
    empty_rationale
        .member_receipts
        .get_mut(&sid("object:aircraft/002"))
        .unwrap()
        .rationale = "   ".to_owned();
    assert_eq!(
        validate_manifest_attention_receipt(&window, &ledger, &materialization, &empty_rationale)
            .unwrap_err()
            .code,
        SharedAttentionFaultCode::InvalidFrame
    );
}

#[test]
fn ledger_change_stales_prior_window_and_host_reads_have_zero_successor() {
    let ledger = ledger();
    let window = compile_accountability_manifest_window(&frame(), &ledger, 100_000).unwrap();
    let changed = apply_accountable_object_patch(
        &ledger,
        AccountableObjectPatch {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            handle: sid("object:aircraft/002"),
            expected_version: 1,
            labels: None,
            differentiators: None,
            state: Some(BTreeMap::from([("readiness".to_owned(), "ready".to_owned())])),
            roles: None,
            purposes: None,
            obligations: None,
            provenance_refs: None,
        },
    )
    .unwrap();
    assert_eq!(
        materialize_accountable_objects(
            &window,
            &changed,
            vec![sid("object:aircraft/001")],
        )
        .unwrap_err()
        .code,
        SharedAttentionFaultCode::StaleLedger
    );

    let journal = new_accounting_journal(sid("journal:manifest"), ledger).unwrap();
    let request = AccountingHostRequest {
        profile: ACCOUNTING_HOST_REQUEST_PROFILE.to_owned(),
        request_id: sid("request:project-manifest"),
        expected_journal_digest: journal.journal_digest.clone(),
        operation: AccountingHostOperation::ProjectManifest {
            frame: Box::new(frame()),
            manifest_byte_budget: 100_000,
        },
    };
    let transition = execute_accounting_host_request(&journal, request).unwrap();
    assert!(transition.successor.is_none());
    assert_eq!(journal.events.len(), 1);
    let AccountingHostResult::ManifestWindow { window } = transition.response.result else {
        panic!("expected manifest window");
    };

    let materialize = AccountingHostRequest {
        profile: ACCOUNTING_HOST_REQUEST_PROFILE.to_owned(),
        request_id: sid("request:materialize"),
        expected_journal_digest: journal.journal_digest.clone(),
        operation: AccountingHostOperation::Materialize {
            frame: Box::new(frame()),
            manifest_byte_budget: 100_000,
            expected_window_digest: window.window_digest.clone(),
            handles: vec![sid("object:aircraft/001")],
        },
    };
    let materialized = execute_accounting_host_request(&journal, materialize).unwrap();
    assert!(materialized.successor.is_none());
    let AccountingHostResult::Materialization { materialization } =
        materialized.response.result
    else {
        panic!("expected materialization");
    };
    let members = BTreeMap::from([
        (
            sid("object:aircraft/001"),
            receipt_member("object:aircraft/001", AttentionMemberDisposition::Relevant),
        ),
        (
            sid("object:aircraft/002"),
            receipt_member(
                "object:aircraft/002",
                AttentionMemberDisposition::NotApplicable,
            ),
        ),
        (
            sid("object:aircraft/003"),
            receipt_member(
                "object:aircraft/003",
                AttentionMemberDisposition::NotApplicable,
            ),
        ),
    ]);
    let acknowledge = AccountingHostRequest {
        profile: ACCOUNTING_HOST_REQUEST_PROFILE.to_owned(),
        request_id: sid("request:acknowledge-attention"),
        expected_journal_digest: journal.journal_digest.clone(),
        operation: AccountingHostOperation::AcknowledgeAttention {
            frame: Box::new(frame()),
            manifest_byte_budget: 100_000,
            expected_window_digest: window.window_digest.clone(),
            materialized_handles: vec![sid("object:aircraft/001")],
            receipt_seed: Box::new(ManifestAttentionReceiptSeed {
                receipt_id: sid("receipt:host-complete"),
                window_digest: window.window_digest.clone(),
                ledger_digest: window.ledger_digest.clone(),
                manifest_digest: window.manifest.manifest_digest.clone(),
                materialization_digest: materialization.materialization_digest.clone(),
                member_receipts: members,
            }),
        },
    };
    let acknowledged = execute_accounting_host_request(&journal, acknowledge).unwrap();
    assert!(acknowledged.successor.is_none());
    let AccountingHostResult::ManifestReceipt { receipt } = acknowledged.response.result else {
        panic!("expected manifest receipt");
    };
    assert_eq!(receipt.status, cantor_core::AttentionReceiptStatus::Complete);
    assert_eq!(journal.events.len(), 1);
}
