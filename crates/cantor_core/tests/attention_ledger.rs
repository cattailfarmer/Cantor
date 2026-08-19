use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ATTENTION_BYTE_PROXY_PROFILE, ATTENTION_COMPACTION_PROFILE, ATTENTION_DELTA_PROFILE,
    AttentionCapacity, AttentionCompaction, AttentionFrameDelta, AttentionLedgerCommand,
    AttentionLedgerDisposition, AttentionParticipant, AttentionSessionOperation,
    AttestationDisposition, ContentDigest, EpistemicStatus, FRAME_ATTESTATION_PROFILE, FacultyKind,
    FrameAttestation, FrameDeltaOperation, FramedProposition, SemanticId, SharedAttentionFaultCode,
    SharedAttentionFrame, SharedAttentionFrameSeed, SharedAttentionToolStatus, SharedFrameStatus,
    execute_attention_ledger_command, finalize_attention_compaction, finalize_attention_delta,
    finalize_frame_attestation, new_attention_ledger, new_shared_attention_frame, sha256_digest,
    validate_attention_ledger,
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

fn rehash_ledger_root(ledger: &mut cantor_core::AttentionLedger) {
    ledger.ledger_digest = empty_digest();
    ledger.ledger_digest = sha256_digest(ledger).expect("fixture ledger root serializes");
}

fn frame(headroom: u64) -> SharedAttentionFrame {
    let guard = AttentionParticipant {
        participant_id: sid("participant:guard"),
        faculties: BTreeSet::from([FacultyKind::Honesty, FacultyKind::Security]),
        required: true,
    };
    let projection = AttentionParticipant {
        participant_id: sid("participant:projection"),
        faculties: BTreeSet::from([FacultyKind::Planner, FacultyKind::Weaver]),
        required: true,
    };
    let server = AttentionParticipant {
        participant_id: sid("participant:server"),
        faculties: BTreeSet::from([
            FacultyKind::Observer,
            FacultyKind::Scribe,
            FacultyKind::Refiner,
        ]),
        required: true,
    };
    let proposition = FramedProposition {
        proposition_id: sid("proposition:ledger-base"),
        text: "The ledger retains exact semantic frame history.".to_owned(),
        epistemic_status: EpistemicStatus::Observed,
        source_refs: BTreeSet::from([sid("source:ledger-fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: None,
    };
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:ledger-fixture"),
        purpose: "prove content-addressed reentry".to_owned(),
        policy_ref: sid("policy:ledger-fixture"),
        participants: BTreeMap::from([
            (guard.participant_id.clone(), guard),
            (projection.participant_id.clone(), projection),
            (server.participant_id.clone(), server),
        ]),
        propositions: BTreeMap::from([(proposition.proposition_id.clone(), proposition)]),
        constraints: BTreeMap::from([(
            sid("constraint:append-only"),
            "history is append-only".to_owned(),
        )]),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::from([sid("proposition:ledger-base")]),
        capacity: AttentionCapacity {
            accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
            context_budget_bytes: 2_000_000,
            pinned_anchor_bytes: 0,
            current_focus_bytes: 100,
            retrieved_association_bytes: 200,
            recent_stream_bytes: 300,
            reserved_headroom_bytes: headroom,
        },
    })
    .expect("fixture frame")
}

fn open(
    initial: SharedAttentionFrame,
) -> (
    cantor_core::AttentionLedger,
    cantor_core::AttentionContinuation,
) {
    let ledger = new_attention_ledger(sid("ledger:fixture")).expect("empty ledger");
    let opened = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::Open {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            session_id: sid("session:fixture"),
            frame: Box::new(initial),
        },
    )
    .expect("open session");
    (
        opened.successor.expect("open successor"),
        opened.response.continuation.expect("open continuation"),
    )
}

fn delta(base: &SharedAttentionFrame, id: &str) -> AttentionFrameDelta {
    finalize_attention_delta(AttentionFrameDelta {
        profile: ATTENTION_DELTA_PROFILE.to_owned(),
        delta_id: sid(id),
        author_ref: sid("participant:guard"),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        logical_time: 1,
        operations: vec![FrameDeltaOperation::AttachEvidence {
            evidence_ref: sid("evidence:ledger-delta"),
        }],
        causal_predecessor_refs: BTreeSet::new(),
        delta_digest: empty_digest(),
    })
    .expect("fixture delta")
}

fn compaction(base: &SharedAttentionFrame) -> AttentionCompaction {
    finalize_attention_compaction(AttentionCompaction {
        profile: ATTENTION_COMPACTION_PROFILE.to_owned(),
        compaction_id: sid("compaction:ledger-fixture"),
        actor_ref: sid("participant:server"),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        retained_focus_refs: BTreeSet::new(),
        current_focus_bytes_after: 0,
        retrieved_association_bytes_after: 0,
        recent_stream_bytes_after: 0,
        rationale: "release completed working-set regions".to_owned(),
        evidence_refs: BTreeSet::from([sid("evidence:ledger-compaction")]),
        compaction_digest: empty_digest(),
    })
    .expect("fixture compaction")
}

fn attestation(
    candidate: &SharedAttentionFrame,
    id: &str,
    participant: &str,
    faculty: FacultyKind,
) -> FrameAttestation {
    finalize_frame_attestation(FrameAttestation {
        profile: FRAME_ATTESTATION_PROFILE.to_owned(),
        attestation_id: sid(id),
        participant_ref: sid(participant),
        faculty,
        candidate_generation: candidate.generation,
        candidate_frame_digest: candidate.frame_digest.clone(),
        disposition: AttestationDisposition::Acknowledge,
        rationale: format!("{faculty:?} accepts exact candidate"),
        evidence_refs: BTreeSet::new(),
        attestation_digest: empty_digest(),
    })
    .expect("fixture attestation")
}

fn complete_attestations(candidate: &SharedAttentionFrame) -> Vec<FrameAttestation> {
    vec![
        attestation(
            candidate,
            "attestation:ledger-honesty",
            "participant:guard",
            FacultyKind::Honesty,
        ),
        attestation(
            candidate,
            "attestation:ledger-security",
            "participant:guard",
            FacultyKind::Security,
        ),
        attestation(
            candidate,
            "attestation:ledger-planner",
            "participant:projection",
            FacultyKind::Planner,
        ),
        attestation(
            candidate,
            "attestation:ledger-observer",
            "participant:server",
            FacultyKind::Observer,
        ),
    ]
}

#[test]
fn open_is_deterministic_content_addressed_and_exactly_readable() {
    let initial = frame(1_000_000);
    let empty = new_attention_ledger(sid("ledger:deterministic")).expect("empty ledger");
    let command = AttentionLedgerCommand::Open {
        expected_ledger_digest: empty.ledger_digest.clone(),
        session_id: sid("session:deterministic"),
        frame: Box::new(initial.clone()),
    };
    let first = execute_attention_ledger_command(&empty, command.clone()).expect("first open");
    let replay = execute_attention_ledger_command(&empty, command).expect("deterministic replay");
    assert_eq!(first, replay);
    let ledger = first.successor.expect("open successor");
    validate_attention_ledger(&ledger).expect("valid ledger");
    assert_eq!(ledger.frames.len(), 1);
    assert_eq!(ledger.sessions.len(), 1);
    assert_eq!(ledger.events.len(), 1);
    let handle = first.response.continuation.expect("continuation");
    assert_eq!(handle.session_sequence, 1);
    assert_eq!(handle.head_frame_digest, initial.frame_digest);

    let read = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::ReadFrame {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            frame_digest: initial.frame_digest.clone(),
        },
    )
    .expect("read frame");
    assert!(read.successor.is_none());
    assert_eq!(read.response.frame, Some(initial));

    let read_event = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::ReadEvent {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            event_id: handle.latest_event_ref.clone(),
        },
    )
    .expect("read event");
    assert!(read_event.successor.is_none());
    assert_eq!(
        read_event
            .response
            .event
            .expect("event projection")
            .event_id,
        handle.latest_event_ref
    );
}

#[test]
fn compact_apply_advances_head_and_stale_replay_has_no_successor() {
    let initial = frame(1);
    let (ledger, handle) = open(initial.clone());
    let command = AttentionLedgerCommand::Apply {
        expected_ledger_digest: ledger.ledger_digest.clone(),
        session_id: handle.session_id.clone(),
        expected_sequence: handle.session_sequence,
        expected_head_frame_digest: handle.head_frame_digest.clone(),
        session_operation: AttentionSessionOperation::Compact {
            compaction: Box::new(compaction(&initial)),
        },
    };
    let applied = execute_attention_ledger_command(&ledger, command.clone()).expect("apply");
    assert_eq!(
        applied.response.disposition,
        AttentionLedgerDisposition::Advanced
    );
    let successor = applied.successor.expect("ledger successor");
    let next = applied.response.continuation.expect("next continuation");
    assert_eq!(next.session_sequence, 2);
    assert_eq!(next.head_generation, initial.generation + 1);
    assert_ne!(next.head_frame_digest, initial.frame_digest);
    assert_eq!(successor.frames.len(), 2);

    let fault = execute_attention_ledger_command(&successor, command)
        .expect_err("old ledger-bound command must be stale");
    assert_eq!(fault.code, SharedAttentionFaultCode::StaleLedger);
}

#[test]
fn buffered_and_refused_attempts_append_events_without_advancing_head() {
    let initial = frame(1);
    let (ledger, handle) = open(initial.clone());
    let buffered = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::Apply {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            session_id: handle.session_id.clone(),
            expected_sequence: handle.session_sequence,
            expected_head_frame_digest: handle.head_frame_digest.clone(),
            session_operation: AttentionSessionOperation::Reconcile {
                deltas: vec![delta(&initial, "delta:ledger-buffered")],
            },
        },
    )
    .expect("buffered attempt");
    assert_eq!(
        buffered.response.disposition,
        AttentionLedgerDisposition::Recorded
    );
    assert_eq!(
        buffered
            .response
            .core_response
            .as_ref()
            .expect("buffered response")
            .status,
        SharedAttentionToolStatus::Buffered
    );
    let buffered_ledger = buffered.successor.expect("recorded ledger");
    let buffered_handle = buffered
        .response
        .continuation
        .expect("recorded continuation");
    assert_eq!(buffered_handle.head_frame_digest, initial.frame_digest);
    assert_eq!(buffered_handle.session_sequence, 2);

    let mut stale_delta = delta(&initial, "delta:ledger-refused");
    stale_delta.base_generation += 1;
    stale_delta = finalize_attention_delta(stale_delta).expect("resign stale delta");
    let refused = execute_attention_ledger_command(
        &buffered_ledger,
        AttentionLedgerCommand::Apply {
            expected_ledger_digest: buffered_ledger.ledger_digest.clone(),
            session_id: buffered_handle.session_id.clone(),
            expected_sequence: buffered_handle.session_sequence,
            expected_head_frame_digest: buffered_handle.head_frame_digest.clone(),
            session_operation: AttentionSessionOperation::Reconcile {
                deltas: vec![stale_delta],
            },
        },
    )
    .expect("semantic refusal is recorded");
    assert_eq!(
        refused.response.disposition,
        AttentionLedgerDisposition::Recorded
    );
    assert_eq!(
        refused
            .response
            .core_response
            .as_ref()
            .expect("refused response")
            .status,
        SharedAttentionToolStatus::Refused
    );
    let refused_handle = refused.response.continuation.expect("refused continuation");
    assert_eq!(refused_handle.head_frame_digest, initial.frame_digest);
    assert_eq!(refused_handle.session_sequence, 3);
    assert_eq!(refused.successor.expect("refusal ledger").events.len(), 3);
}

#[test]
fn prepare_and_settle_form_one_auditable_candidate_to_sealed_trajectory() {
    let initial = frame(1_000_000);
    let (ledger, handle) = open(initial);
    let prepared = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::Apply {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            session_id: handle.session_id.clone(),
            expected_sequence: handle.session_sequence,
            expected_head_frame_digest: handle.head_frame_digest,
            session_operation: AttentionSessionOperation::Prepare,
        },
    )
    .expect("prepare");
    let prepared_ledger = prepared.successor.expect("prepared ledger");
    let prepared_handle = prepared
        .response
        .continuation
        .expect("prepared continuation");
    assert_eq!(
        prepared_handle.head_status,
        SharedFrameStatus::CandidateFrozen
    );
    let candidate = prepared_ledger
        .frames
        .get(&prepared_handle.head_frame_digest.value)
        .expect("candidate frame");

    let settled = execute_attention_ledger_command(
        &prepared_ledger,
        AttentionLedgerCommand::Apply {
            expected_ledger_digest: prepared_ledger.ledger_digest.clone(),
            session_id: prepared_handle.session_id.clone(),
            expected_sequence: prepared_handle.session_sequence,
            expected_head_frame_digest: prepared_handle.head_frame_digest,
            session_operation: AttentionSessionOperation::Settle {
                attestations: complete_attestations(candidate),
            },
        },
    )
    .expect("settle");
    let handle = settled.response.continuation.expect("sealed continuation");
    assert_eq!(handle.head_status, SharedFrameStatus::Sealed);
    assert_eq!(handle.session_sequence, 3);
    assert_eq!(settled.successor.expect("sealed ledger").frames.len(), 3);
}

#[test]
fn stale_unknown_strict_and_tampered_inputs_fail_closed() {
    let initial = frame(1_000_000);
    let (ledger, handle) = open(initial);
    let stale = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::Inspect {
            expected_ledger_digest: empty_digest(),
            session_id: handle.session_id.clone(),
        },
    )
    .expect_err("bad root digest");
    assert_eq!(stale.code, SharedAttentionFaultCode::StaleLedger);

    let unknown_session = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::Inspect {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            session_id: sid("session:absent"),
        },
    )
    .expect_err("unknown session");
    assert_eq!(
        unknown_session.code,
        SharedAttentionFaultCode::UnknownSession
    );
    let unknown_event = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::ReadEvent {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            event_id: sid("event:absent"),
        },
    )
    .expect_err("unknown event");
    assert_eq!(unknown_event.code, SharedAttentionFaultCode::UnknownEvent);

    let unknown_frame = execute_attention_ledger_command(
        &ledger,
        AttentionLedgerCommand::ReadFrame {
            expected_ledger_digest: ledger.ledger_digest.clone(),
            frame_digest: cantor_core::sha256_bytes(b"absent frame"),
        },
    )
    .expect_err("unknown frame");
    assert_eq!(
        unknown_frame.code,
        SharedAttentionFaultCode::UnknownReference
    );

    let mut tampered = ledger.clone();
    tampered.ledger_digest.value.replace_range(0..1, "0");
    if tampered.ledger_digest == ledger.ledger_digest {
        tampered.ledger_digest.value.replace_range(0..1, "1");
    }
    assert_eq!(
        validate_attention_ledger(&tampered)
            .expect_err("tampered root")
            .code,
        SharedAttentionFaultCode::InvalidDigest
    );

    let mut tampered_frame = ledger.clone();
    tampered_frame
        .frames
        .values_mut()
        .next()
        .expect("stored frame")
        .purpose
        .push_str(" changed");
    rehash_ledger_root(&mut tampered_frame);
    assert_eq!(
        validate_attention_ledger(&tampered_frame)
            .expect_err("tampered frame")
            .code,
        SharedAttentionFaultCode::InvalidDigest
    );

    let mut tampered_session = ledger.clone();
    tampered_session
        .sessions
        .values_mut()
        .next()
        .expect("stored session")
        .session_digest = empty_digest();
    rehash_ledger_root(&mut tampered_session);
    assert_eq!(
        validate_attention_ledger(&tampered_session)
            .expect_err("tampered session")
            .code,
        SharedAttentionFaultCode::InvalidDigest
    );

    let mut tampered_event = ledger.clone();
    tampered_event
        .events
        .values_mut()
        .next()
        .expect("stored event")
        .event_digest = empty_digest();
    rehash_ledger_root(&mut tampered_event);
    assert_eq!(
        validate_attention_ledger(&tampered_event)
            .expect_err("tampered event")
            .code,
        SharedAttentionFaultCode::InvalidDigest
    );

    let mut value = serde_json::to_value(AttentionLedgerCommand::Inspect {
        expected_ledger_digest: ledger.ledger_digest,
        session_id: handle.session_id,
    })
    .expect("command JSON");
    value["invented_authority"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<AttentionLedgerCommand>(value).is_err());
}
