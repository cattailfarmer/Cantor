use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ATTENTION_BYTE_PROXY_PROFILE, ATTENTION_COMPACTION_PROFILE, ATTENTION_DELTA_PROFILE,
    AttentionCapacity, AttentionCompaction, AttentionFrameDelta, AttentionParticipant,
    AttestationDisposition, ContentDigest, DREAM_REVIEW_PROFILE, DreamFrame, DreamFrameSeed,
    DreamReview, DreamReviewDisposition, DreamStatus, EpistemicStatus, FRAME_ATTESTATION_PROFILE,
    FacultyKind, FrameAttestation, FrameDeltaOperation, FramedProposition,
    ReconciliationDisposition, SemanticId, SettlementDisposition, SharedAttentionFaultCode,
    SharedAttentionFrame, SharedAttentionFrameSeed, SharedAttentionToolRequest,
    SharedAttentionToolResult, SharedAttentionToolStatus, SharedFrameStatus,
    compact_attention_frame, compute_delta_digest, discard_dream_frame,
    execute_shared_attention_tool_request, finalize_attention_compaction, finalize_attention_delta,
    finalize_dream_review, finalize_frame_attestation, fork_dream_frame, from_machine_form,
    new_shared_attention_frame, prepare_attention_candidate, project_dream_promotion,
    reconcile_attention_deltas, record_dream_evidence, review_dream_frame,
    settle_attention_candidate, to_machine_form, validate_dream_frame,
    validate_shared_attention_frame,
};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("semantic id")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn proposition(
    id: &str,
    text: &str,
    epistemic_status: EpistemicStatus,
    dream_ref: Option<&str>,
) -> FramedProposition {
    FramedProposition {
        proposition_id: sid(id),
        text: text.to_owned(),
        epistemic_status,
        source_refs: BTreeSet::from([sid("source:fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: dream_ref.map(sid),
    }
}

fn participants() -> BTreeMap<SemanticId, AttentionParticipant> {
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
    BTreeMap::from([
        (guard.participant_id.clone(), guard),
        (projection.participant_id.clone(), projection),
        (server.participant_id.clone(), server),
    ])
}

fn frame_with_headroom(headroom: u64) -> SharedAttentionFrame {
    let base = proposition(
        "proposition:base",
        "Cantor coordinates transportable semantic state.",
        EpistemicStatus::Observed,
        None,
    );
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:fixture"),
        purpose: "coordinate a bounded inference pass".to_owned(),
        policy_ref: sid("policy:fixture"),
        participants: participants(),
        propositions: BTreeMap::from([(base.proposition_id.clone(), base)]),
        constraints: BTreeMap::from([(
            sid("constraint:identity"),
            "shared state is semantic state, not hidden model state".to_owned(),
        )]),
        pinned_sop_anchor_refs: BTreeSet::from([sid("anchor:sop-core")]),
        evidence_refs: BTreeSet::from([sid("evidence:source-lock")]),
        current_focus_refs: BTreeSet::from([sid("proposition:base")]),
        capacity: AttentionCapacity {
            accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
            context_budget_bytes: 2_000_000,
            pinned_anchor_bytes: 100,
            current_focus_bytes: 200,
            retrieved_association_bytes: 300,
            recent_stream_bytes: 400,
            reserved_headroom_bytes: headroom,
        },
    })
    .expect("fixture frame")
}

fn delta(
    base: &SharedAttentionFrame,
    id: &str,
    author: &str,
    logical_time: u64,
    operations: Vec<FrameDeltaOperation>,
) -> AttentionFrameDelta {
    finalize_attention_delta(AttentionFrameDelta {
        profile: ATTENTION_DELTA_PROFILE.to_owned(),
        delta_id: sid(id),
        author_ref: sid(author),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        logical_time,
        operations,
        causal_predecessor_refs: BTreeSet::new(),
        delta_digest: empty_digest(),
    })
    .expect("fixture delta")
}

fn compaction(base: &SharedAttentionFrame, id: &str, actor: &str) -> AttentionCompaction {
    finalize_attention_compaction(AttentionCompaction {
        profile: ATTENTION_COMPACTION_PROFILE.to_owned(),
        compaction_id: sid(id),
        actor_ref: sid(actor),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        retained_focus_refs: BTreeSet::new(),
        current_focus_bytes_after: 0,
        retrieved_association_bytes_after: 0,
        recent_stream_bytes_after: 0,
        rationale: "release the completed focus and preserve its evidence".to_owned(),
        evidence_refs: BTreeSet::from([sid("evidence:compaction")]),
        compaction_digest: empty_digest(),
    })
    .expect("fixture compaction")
}

fn attestation(
    candidate: &SharedAttentionFrame,
    id: &str,
    participant: &str,
    faculty: FacultyKind,
    disposition: AttestationDisposition,
) -> FrameAttestation {
    finalize_frame_attestation(FrameAttestation {
        profile: FRAME_ATTESTATION_PROFILE.to_owned(),
        attestation_id: sid(id),
        participant_ref: sid(participant),
        faculty,
        candidate_generation: candidate.generation,
        candidate_frame_digest: candidate.frame_digest.clone(),
        disposition,
        rationale: format!("{faculty:?} fixture review"),
        evidence_refs: BTreeSet::new(),
        attestation_digest: empty_digest(),
    })
    .expect("fixture attestation")
}

fn complete_attestations(candidate: &SharedAttentionFrame) -> Vec<FrameAttestation> {
    vec![
        attestation(
            candidate,
            "attestation:honesty",
            "participant:guard",
            FacultyKind::Honesty,
            AttestationDisposition::Acknowledge,
        ),
        attestation(
            candidate,
            "attestation:security",
            "participant:guard",
            FacultyKind::Security,
            AttestationDisposition::Acknowledge,
        ),
        attestation(
            candidate,
            "attestation:planner",
            "participant:projection",
            FacultyKind::Planner,
            AttestationDisposition::Acknowledge,
        ),
        attestation(
            candidate,
            "attestation:observer",
            "participant:server",
            FacultyKind::Observer,
            AttestationDisposition::Acknowledge,
        ),
    ]
}

fn sealed_frame() -> SharedAttentionFrame {
    let prepared =
        prepare_attention_candidate(&frame_with_headroom(1_000_000)).expect("prepared candidate");
    settle_attention_candidate(
        &prepared.candidate,
        &complete_attestations(&prepared.candidate),
    )
    .expect("settlement")
    .sealed_frame
    .expect("sealed frame")
}

fn dream_seed(parent: &SharedAttentionFrame) -> DreamFrameSeed {
    let hypothesis = proposition(
        "proposition:dream-route",
        "A clustered frame may reduce repeated retrieval.",
        EpistemicStatus::Imagined,
        Some("dream:fixture"),
    );
    DreamFrameSeed {
        dream_id: sid("dream:fixture"),
        parent_frame_digest: parent.frame_digest.clone(),
        purpose: "explore a bounded coordination alternative".to_owned(),
        preserved_invariant_refs: BTreeSet::from([sid("constraint:identity")]),
        relaxed_assumptions: BTreeMap::from([(
            sid("assumption:cluster"),
            "one frame may be split into clustered subordinate views".to_owned(),
        )]),
        forbidden_effects: BTreeSet::from(["all_external_effects".to_owned()]),
        hypotheses: BTreeMap::from([(hypothesis.proposition_id.clone(), hypothesis)]),
        predicted_consequences: BTreeMap::from([(
            sid("consequence:retrieval"),
            "less irrelevant material remains in current focus".to_owned(),
        )]),
        required_evidence_refs: BTreeSet::from([sid("evidence:dream-test")]),
        falsification_conditions: BTreeSet::from([
            "retrieval cost does not improve under the same workload".to_owned(),
        ]),
        depth: 1,
        maximum_depth: 2,
    }
}

fn dream_review(
    dream: &DreamFrame,
    id: &str,
    reviewer: &str,
    faculty: FacultyKind,
    disposition: AttestationDisposition,
) -> DreamReview {
    finalize_dream_review(DreamReview {
        profile: DREAM_REVIEW_PROFILE.to_owned(),
        review_id: sid(id),
        dream_ref: dream.dream_id.clone(),
        base_dream_digest: dream.dream_digest.clone(),
        reviewer_ref: sid(reviewer),
        faculty,
        disposition,
        rationale: format!("{faculty:?} dream review"),
        evidence_refs: BTreeSet::from([sid("evidence:dream-test")]),
        review_digest: empty_digest(),
    })
    .expect("fixture dream review")
}

fn gate_dream_reviews(dream: &DreamFrame) -> Vec<DreamReview> {
    vec![
        dream_review(
            dream,
            "dream-review:honesty",
            "participant:guard",
            FacultyKind::Honesty,
            AttestationDisposition::Acknowledge,
        ),
        dream_review(
            dream,
            "dream-review:security",
            "participant:guard",
            FacultyKind::Security,
            AttestationDisposition::Acknowledge,
        ),
        dream_review(
            dream,
            "dream-review:observer",
            "participant:server",
            FacultyKind::Observer,
            AttestationDisposition::Acknowledge,
        ),
    ]
}

#[test]
fn genesis_is_deterministic_and_machine_form_round_trips() {
    let first = frame_with_headroom(1_000_000);
    let second = frame_with_headroom(1_000_000);
    assert_eq!(first, second);
    assert_eq!(first.generation, 0);
    assert_eq!(first.status, SharedFrameStatus::Working);
    assert_ne!(first.semantic_digest.value, "");
    assert_ne!(first.frame_digest.value, "");

    let encoded = to_machine_form(&first).expect("encode frame");
    let decoded: SharedAttentionFrame = from_machine_form(&encoded).expect("decode frame");
    assert_eq!(decoded, first);
    validate_shared_attention_frame(&decoded).expect("validate decoded frame");
}

#[test]
fn nonconflicting_delta_batch_is_order_independent_and_replayable() {
    let base = frame_with_headroom(1_000_000);
    let first = delta(
        &base,
        "delta:add",
        "participant:projection",
        2,
        vec![FrameDeltaOperation::AddProposition {
            proposition: proposition(
                "proposition:route",
                "Planner proposes one bounded route.",
                EpistemicStatus::Inferred,
                None,
            ),
        }],
    );
    let second = delta(
        &base,
        "delta:constraint",
        "participant:guard",
        1,
        vec![FrameDeltaOperation::AddConstraint {
            constraint_id: sid("constraint:no-effects"),
            text: "the frame performs no external effect".to_owned(),
        }],
    );
    let base_before = base.clone();
    let left = reconcile_attention_deltas(&base, &[first.clone(), second.clone()])
        .expect("left reconciliation");
    let right = reconcile_attention_deltas(&base, &[second, first]).expect("right reconciliation");
    assert_eq!(left, right);
    assert_eq!(left.disposition, ReconciliationDisposition::Applied);
    assert_eq!(base, base_before);
    let successor = left.successor.expect("successor");
    assert_eq!(successor.generation, 1);
    assert_eq!(successor.predecessor_frame_digest, Some(base.frame_digest));
    assert!(
        successor
            .propositions
            .contains_key(&sid("proposition:route"))
    );
    assert!(
        successor
            .constraints
            .contains_key(&sid("constraint:no-effects"))
    );
    assert!(left.transition_receipt.is_some());
    assert!(left.backpressure_receipt.is_none());
}

#[test]
fn stale_base_bad_digest_and_unknown_participant_refuse_atomically() {
    let base = frame_with_headroom(1_000_000);
    let operation = vec![FrameDeltaOperation::AttachEvidence {
        evidence_ref: sid("evidence:new"),
    }];
    let mut stale = delta(
        &base,
        "delta:stale",
        "participant:guard",
        1,
        operation.clone(),
    );
    stale.base_generation += 1;
    stale = finalize_attention_delta(stale).expect("resign stale fixture");
    let before = base.clone();
    assert_eq!(
        reconcile_attention_deltas(&base, &[stale])
            .expect_err("stale base")
            .code,
        SharedAttentionFaultCode::StaleBase
    );
    assert_eq!(base, before);

    let mut corrupt = delta(
        &base,
        "delta:corrupt",
        "participant:guard",
        1,
        operation.clone(),
    );
    corrupt.delta_digest.value.push('0');
    assert_eq!(
        reconcile_attention_deltas(&base, &[corrupt])
            .expect_err("bad digest")
            .code,
        SharedAttentionFaultCode::InvalidDigest
    );

    let unknown = delta(&base, "delta:unknown", "participant:unknown", 1, operation);
    assert_eq!(
        reconcile_attention_deltas(&base, &[unknown])
            .expect_err("unknown participant")
            .code,
        SharedAttentionFaultCode::UnknownParticipant
    );
    assert_eq!(base, before);
}

#[test]
fn conflicting_targets_and_unknown_references_refuse_the_whole_batch() {
    let base = frame_with_headroom(1_000_000);
    let add = FrameDeltaOperation::AddConstraint {
        constraint_id: sid("constraint:collision"),
        text: "first".to_owned(),
    };
    let first = delta(&base, "delta:a", "participant:guard", 1, vec![add.clone()]);
    let second = delta(&base, "delta:b", "participant:server", 2, vec![add]);
    assert_eq!(
        reconcile_attention_deltas(&base, &[first, second])
            .expect_err("conflict")
            .code,
        SharedAttentionFaultCode::ConflictingMutation
    );

    let bad_reference = delta(
        &base,
        "delta:missing",
        "participant:projection",
        3,
        vec![FrameDeltaOperation::SetFocus {
            proposition_ref: sid("proposition:missing"),
        }],
    );
    assert_eq!(
        reconcile_attention_deltas(&base, &[bad_reference])
            .expect_err("missing proposition")
            .code,
        SharedAttentionFaultCode::UnknownReference
    );
    assert!(
        !base
            .current_focus_refs
            .contains(&sid("proposition:missing"))
    );
}

#[test]
fn imagined_proposition_cannot_enter_a_reality_delta() {
    let base = frame_with_headroom(1);
    let imagined = delta(
        &base,
        "delta:imagined",
        "participant:projection",
        1,
        vec![FrameDeltaOperation::AddProposition {
            proposition: proposition(
                "proposition:unbounded-imagination",
                "An unreviewed possibility.",
                EpistemicStatus::Imagined,
                Some("dream:missing"),
            ),
        }],
    );
    assert_eq!(
        reconcile_attention_deltas(&base, &[imagined])
            .expect_err("imagined reality mutation")
            .code,
        SharedAttentionFaultCode::EpistemicBoundary
    );
}

#[test]
fn excess_novelty_buffers_and_does_not_mutate_the_frame() {
    let base = frame_with_headroom(1);
    let before = base.clone();
    let incoming = delta(
        &base,
        "delta:large",
        "participant:projection",
        1,
        vec![FrameDeltaOperation::AddProposition {
            proposition: proposition(
                "proposition:novel",
                "This payload is necessarily larger than one canonical byte.",
                EpistemicStatus::Assumed,
                None,
            ),
        }],
    );
    let outcome = reconcile_attention_deltas(&base, &[incoming]).expect("backpressure outcome");
    assert_eq!(outcome.disposition, ReconciliationDisposition::Buffered);
    assert!(outcome.successor.is_none());
    assert!(outcome.transition_receipt.is_none());
    let receipt = outcome.backpressure_receipt.expect("backpressure receipt");
    assert!(receipt.required_novelty_bytes > receipt.available_headroom_bytes);
    assert_eq!(receipt.available_headroom_bytes, 1);
    assert!(
        receipt
            .recovery_actions
            .contains(&"freeze_frame".to_owned())
    );
    assert!(
        receipt
            .recovery_actions
            .contains(&"prioritize_authority_identity_security".to_owned())
    );
    assert_eq!(base, before);
}

#[test]
fn candidate_preparation_rejects_unresolved_challenges() {
    let base = frame_with_headroom(1_000_000);
    let challenge = delta(
        &base,
        "delta:challenge",
        "participant:guard",
        1,
        vec![FrameDeltaOperation::RaiseChallenge {
            challenge_id: sid("challenge:identity"),
            text: "the proposed identity is under-specified".to_owned(),
        }],
    );
    let working = reconcile_attention_deltas(&base, &[challenge])
        .expect("challenge transition")
        .successor
        .expect("working successor");
    assert_eq!(
        prepare_attention_candidate(&working)
            .expect_err("challenge blocks freeze")
            .code,
        SharedAttentionFaultCode::UnresolvedChallenge
    );
}

#[test]
fn complete_exact_role_bound_attestations_seal_without_reclassifying_meaning() {
    let working = frame_with_headroom(1_000_000);
    let prepared = prepare_attention_candidate(&working).expect("prepare");
    assert_eq!(
        prepared.candidate.status,
        SharedFrameStatus::CandidateFrozen
    );
    assert_eq!(prepared.candidate.semantic_digest, working.semantic_digest);
    let outcome = settle_attention_candidate(
        &prepared.candidate,
        &complete_attestations(&prepared.candidate),
    )
    .expect("settlement");
    assert_eq!(outcome.disposition, SettlementDisposition::Sealed);
    let sealed = outcome.sealed_frame.expect("sealed frame");
    assert_eq!(sealed.status, SharedFrameStatus::Sealed);
    assert_eq!(sealed.semantic_digest, prepared.candidate.semantic_digest);
    assert_eq!(
        sealed
            .propositions
            .get(&sid("proposition:base"))
            .expect("base proposition")
            .epistemic_status,
        EpistemicStatus::Observed
    );
    assert_eq!(
        outcome.receipt.sealed_frame_digest,
        Some(sealed.frame_digest.clone())
    );
    assert_eq!(
        sealed.settlement_attestation_refs,
        outcome.receipt.attestation_refs
    );
}

#[test]
fn incomplete_deferred_and_challenged_attestations_cannot_seal() {
    let candidate = prepare_attention_candidate(&frame_with_headroom(1_000_000))
        .expect("prepare")
        .candidate;
    let incomplete = settle_attention_candidate(
        &candidate,
        &[attestation(
            &candidate,
            "attestation:only-observer",
            "participant:server",
            FacultyKind::Observer,
            AttestationDisposition::Acknowledge,
        )],
    )
    .expect("incomplete outcome");
    assert_eq!(incomplete.disposition, SettlementDisposition::Incomplete);
    assert!(incomplete.sealed_frame.is_none());
    assert!(!incomplete.receipt.missing_participant_refs.is_empty());
    assert!(
        incomplete
            .receipt
            .missing_gate_faculties
            .contains(&FacultyKind::Honesty)
    );

    let mut deferred_attestations = complete_attestations(&candidate);
    deferred_attestations[0] = attestation(
        &candidate,
        "attestation:honesty-defer",
        "participant:guard",
        FacultyKind::Honesty,
        AttestationDisposition::Defer,
    );
    let deferred =
        settle_attention_candidate(&candidate, &deferred_attestations).expect("deferred outcome");
    assert_eq!(deferred.disposition, SettlementDisposition::Deferred);
    assert!(deferred.sealed_frame.is_none());

    let mut challenged_attestations = complete_attestations(&candidate);
    challenged_attestations[0] = attestation(
        &candidate,
        "attestation:honesty-challenge",
        "participant:guard",
        FacultyKind::Honesty,
        AttestationDisposition::Challenge,
    );
    let challenged = settle_attention_candidate(&candidate, &challenged_attestations)
        .expect("challenged outcome");
    assert_eq!(
        challenged.disposition,
        SettlementDisposition::RevisionRequired
    );
    assert!(challenged.sealed_frame.is_none());
}

#[test]
fn stale_or_unauthorized_attestation_is_a_typed_fault() {
    let candidate = prepare_attention_candidate(&frame_with_headroom(1_000_000))
        .expect("prepare")
        .candidate;
    let mut stale = attestation(
        &candidate,
        "attestation:stale",
        "participant:server",
        FacultyKind::Observer,
        AttestationDisposition::Acknowledge,
    );
    stale.candidate_generation += 1;
    stale = finalize_frame_attestation(stale).expect("resign stale attestation");
    assert_eq!(
        settle_attention_candidate(&candidate, &[stale])
            .expect_err("stale attestation")
            .code,
        SharedAttentionFaultCode::StaleBase
    );

    let unauthorized = attestation(
        &candidate,
        "attestation:wrong-role",
        "participant:projection",
        FacultyKind::Security,
        AttestationDisposition::Acknowledge,
    );
    assert_eq!(
        settle_attention_candidate(&candidate, &[unauthorized])
            .expect_err("unauthorized faculty")
            .code,
        SharedAttentionFaultCode::UnauthorizedFaculty
    );
}

#[test]
fn dream_requires_exact_sealed_parent_and_hypothetical_lineage() {
    let working = frame_with_headroom(1_000_000);
    assert_eq!(
        fork_dream_frame(&working, dream_seed(&working))
            .expect_err("unsealed parent")
            .code,
        SharedAttentionFaultCode::DreamBoundary
    );

    let sealed = sealed_frame();
    let mut stale_seed = dream_seed(&sealed);
    stale_seed.parent_frame_digest.value.push('0');
    assert_eq!(
        fork_dream_frame(&sealed, stale_seed)
            .expect_err("stale parent")
            .code,
        SharedAttentionFaultCode::StaleBase
    );

    let mut wrong_label = dream_seed(&sealed);
    wrong_label
        .hypotheses
        .get_mut(&sid("proposition:dream-route"))
        .expect("hypothesis")
        .epistemic_status = EpistemicStatus::Inferred;
    assert_eq!(
        fork_dream_frame(&sealed, wrong_label)
            .expect_err("wrong epistemic label")
            .code,
        SharedAttentionFaultCode::EpistemicBoundary
    );
}

#[test]
fn dream_evidence_gate_review_and_promotion_preserve_parent() {
    let parent = sealed_frame();
    let parent_before = parent.clone();
    let dream = fork_dream_frame(&parent, dream_seed(&parent)).expect("fork dream");
    assert_eq!(dream.status, DreamStatus::Open);
    let testing = record_dream_evidence(
        &parent,
        &dream,
        &BTreeSet::from([sid("evidence:dream-test")]),
    )
    .expect("record evidence");
    assert_eq!(testing.status, DreamStatus::Testing);
    let outcome =
        review_dream_frame(&parent, &testing, &gate_dream_reviews(&testing)).expect("review dream");
    assert_eq!(outcome.disposition, DreamReviewDisposition::Verified);
    let verified = outcome.successor.expect("verified dream");
    assert_eq!(verified.status, DreamStatus::Verified);
    assert_eq!(
        verified.verification_review_refs,
        outcome.receipt.review_refs
    );

    let promotion = project_dream_promotion(
        &parent,
        &verified,
        sid("delta:dream-promotion"),
        sid("participant:projection"),
        EpistemicStatus::Inferred,
        10,
    )
    .expect("promotion delta");
    assert_eq!(promotion.base_frame_digest, parent.frame_digest);
    assert_eq!(promotion.base_generation, parent.generation);
    assert!(
        verified
            .verification_review_refs
            .is_subset(&promotion.causal_predecessor_refs)
    );
    assert_eq!(parent, parent_before);

    let promoted = reconcile_attention_deltas(&parent, &[promotion])
        .expect("reconcile promotion")
        .successor
        .expect("promoted working frame");
    let proposition = promoted
        .propositions
        .get(&sid("proposition:dream-route"))
        .expect("promoted proposition");
    assert_eq!(proposition.epistemic_status, EpistemicStatus::Inferred);
    assert_eq!(proposition.dream_ref, Some(verified.dream_id));
    assert!(
        proposition
            .evidence_refs
            .contains(&sid("evidence:dream-test"))
    );
    assert_eq!(promoted.status, SharedFrameStatus::Working);
    assert_eq!(parent, parent_before);
}

#[test]
fn dream_review_dissent_or_missing_gate_cannot_verify() {
    let parent = sealed_frame();
    let dream = fork_dream_frame(&parent, dream_seed(&parent)).expect("fork dream");
    let testing = record_dream_evidence(
        &parent,
        &dream,
        &BTreeSet::from([sid("evidence:dream-test")]),
    )
    .expect("testing dream");
    let incomplete = review_dream_frame(
        &parent,
        &testing,
        &[dream_review(
            &testing,
            "dream-review:observer-only",
            "participant:server",
            FacultyKind::Observer,
            AttestationDisposition::Acknowledge,
        )],
    )
    .expect("incomplete review");
    assert_eq!(incomplete.disposition, DreamReviewDisposition::Incomplete);
    assert!(incomplete.successor.is_none());

    let mut challenged_reviews = gate_dream_reviews(&testing);
    challenged_reviews[0] = dream_review(
        &testing,
        "dream-review:honesty-challenge",
        "participant:guard",
        FacultyKind::Honesty,
        AttestationDisposition::Challenge,
    );
    let challenged =
        review_dream_frame(&parent, &testing, &challenged_reviews).expect("challenged review");
    assert_eq!(
        challenged.disposition,
        DreamReviewDisposition::RevisionRequired
    );
    assert!(challenged.successor.is_none());
}

#[test]
fn unverified_dream_cannot_project_and_verified_dream_cannot_claim_observed() {
    let parent = sealed_frame();
    let dream = fork_dream_frame(&parent, dream_seed(&parent)).expect("fork dream");
    assert_eq!(
        project_dream_promotion(
            &parent,
            &dream,
            sid("delta:too-early"),
            sid("participant:projection"),
            EpistemicStatus::Assumed,
            1,
        )
        .expect_err("unverified promotion")
        .code,
        SharedAttentionFaultCode::DreamBoundary
    );
    let testing = record_dream_evidence(
        &parent,
        &dream,
        &BTreeSet::from([sid("evidence:dream-test")]),
    )
    .expect("testing dream");
    let verified = review_dream_frame(&parent, &testing, &gate_dream_reviews(&testing))
        .expect("verified review")
        .successor
        .expect("verified dream");
    assert_eq!(
        project_dream_promotion(
            &parent,
            &verified,
            sid("delta:false-observation"),
            sid("participant:projection"),
            EpistemicStatus::Observed,
            2,
        )
        .expect_err("observed promotion")
        .code,
        SharedAttentionFaultCode::EpistemicBoundary
    );
}

#[test]
fn dream_machine_form_round_trip_rejects_unknown_fields() {
    let parent = sealed_frame();
    let dream = fork_dream_frame(&parent, dream_seed(&parent)).expect("fork dream");
    let encoded = to_machine_form(&dream).expect("encode dream");
    let decoded: DreamFrame = from_machine_form(&encoded).expect("decode dream");
    assert_eq!(decoded, dream);
    validate_dream_frame(&parent, &decoded).expect("validate decoded dream");

    let mut value: serde_json::Value = serde_json::from_str(&encoded).expect("JSON value");
    value["unknown_authority"] = serde_json::json!(true);
    let unknown = serde_json::to_string(&value).expect("unknown-field JSON");
    assert!(from_machine_form::<DreamFrame>(&unknown).is_err());
}

#[test]
fn digest_changes_are_detected_after_serialized_content_tampering() {
    let base = frame_with_headroom(1_000_000);
    let mut value: serde_json::Value =
        serde_json::from_str(&to_machine_form(&base).expect("encode frame")).expect("frame JSON");
    value["purpose"] = serde_json::json!("tampered purpose");
    let tampered: SharedAttentionFrame = serde_json::from_value(value).expect("typed tamper");
    assert_eq!(
        validate_shared_attention_frame(&tampered)
            .expect_err("digest mismatch")
            .code,
        SharedAttentionFaultCode::InvalidDigest
    );

    let incoming = delta(
        &base,
        "delta:digest-check",
        "participant:guard",
        1,
        vec![FrameDeltaOperation::AttachEvidence {
            evidence_ref: sid("evidence:digest-check"),
        }],
    );
    assert_eq!(
        incoming.delta_digest,
        compute_delta_digest(&incoming).expect("delta digest")
    );
}

#[test]
fn every_delta_operator_has_a_successful_generation_bound_transition() {
    let base = frame_with_headroom(1_000_000);
    let first = delta(
        &base,
        "delta:operator-generation-one",
        "participant:projection",
        1,
        vec![
            FrameDeltaOperation::ReplaceProposition {
                proposition: proposition(
                    "proposition:base",
                    "Cantor coordinates an exact transportable semantic frame.",
                    EpistemicStatus::Verified,
                    None,
                ),
            },
            FrameDeltaOperation::AddProposition {
                proposition: proposition(
                    "proposition:temporary",
                    "This proposition exists for one generation.",
                    EpistemicStatus::Assumed,
                    None,
                ),
            },
            FrameDeltaOperation::AddConstraint {
                constraint_id: sid("constraint:temporary"),
                text: "temporary constraint".to_owned(),
            },
            FrameDeltaOperation::PinAnchor {
                anchor_ref: sid("anchor:temporary"),
            },
            FrameDeltaOperation::AttachEvidence {
                evidence_ref: sid("evidence:temporary"),
            },
            FrameDeltaOperation::RaiseChallenge {
                challenge_id: sid("challenge:temporary"),
                text: "temporary challenge".to_owned(),
            },
            FrameDeltaOperation::ReleaseFocus {
                proposition_ref: sid("proposition:base"),
            },
        ],
    );
    let generation_one = reconcile_attention_deltas(&base, &[first])
        .expect("first operator generation")
        .successor
        .expect("first successor");
    assert_eq!(generation_one.generation, 1);
    assert!(generation_one.current_focus_refs.is_empty());
    assert!(
        generation_one
            .challenges
            .contains_key(&sid("challenge:temporary"))
    );

    let second = delta(
        &generation_one,
        "delta:operator-generation-two",
        "participant:guard",
        2,
        vec![
            FrameDeltaOperation::RemoveProposition {
                proposition_ref: sid("proposition:temporary"),
            },
            FrameDeltaOperation::RemoveConstraint {
                constraint_ref: sid("constraint:temporary"),
            },
            FrameDeltaOperation::ReleaseAnchor {
                anchor_ref: sid("anchor:temporary"),
            },
            FrameDeltaOperation::ResolveChallenge {
                challenge_ref: sid("challenge:temporary"),
            },
            FrameDeltaOperation::SetFocus {
                proposition_ref: sid("proposition:base"),
            },
        ],
    );
    let generation_two = reconcile_attention_deltas(&generation_one, &[second])
        .expect("second operator generation")
        .successor
        .expect("second successor");
    assert_eq!(generation_two.generation, 2);
    assert!(
        !generation_two
            .propositions
            .contains_key(&sid("proposition:temporary"))
    );
    assert!(
        !generation_two
            .constraints
            .contains_key(&sid("constraint:temporary"))
    );
    assert!(
        !generation_two
            .pinned_sop_anchor_refs
            .contains(&sid("anchor:temporary"))
    );
    assert!(generation_two.challenges.is_empty());
    assert!(
        generation_two
            .current_focus_refs
            .contains(&sid("proposition:base"))
    );
}

#[test]
fn applied_delta_identity_cannot_be_replayed_on_a_later_generation() {
    let base = frame_with_headroom(1_000_000);
    let first = delta(
        &base,
        "delta:one-shot",
        "participant:guard",
        1,
        vec![FrameDeltaOperation::AttachEvidence {
            evidence_ref: sid("evidence:one-shot"),
        }],
    );
    let successor = reconcile_attention_deltas(&base, &[first])
        .expect("first application")
        .successor
        .expect("successor");
    let replay = delta(
        &successor,
        "delta:one-shot",
        "participant:guard",
        2,
        vec![FrameDeltaOperation::AttachEvidence {
            evidence_ref: sid("evidence:second"),
        }],
    );
    assert_eq!(
        reconcile_attention_deltas(&successor, &[replay])
            .expect_err("replayed identity")
            .code,
        SharedAttentionFaultCode::DuplicateIdentity
    );
}

#[test]
fn capacity_arithmetic_and_mandatory_gate_declarations_fail_closed() {
    let mut seed = SharedAttentionFrameSeed {
        frame_id: sid("frame:bad-capacity"),
        purpose: "exercise overflow".to_owned(),
        policy_ref: sid("policy:fixture"),
        participants: participants(),
        propositions: BTreeMap::new(),
        constraints: BTreeMap::new(),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::new(),
        capacity: AttentionCapacity {
            accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
            context_budget_bytes: u64::MAX,
            pinned_anchor_bytes: u64::MAX,
            current_focus_bytes: 1,
            retrieved_association_bytes: 0,
            recent_stream_bytes: 0,
            reserved_headroom_bytes: 0,
        },
    };
    assert_eq!(
        new_shared_attention_frame(seed.clone())
            .expect_err("capacity overflow")
            .code,
        SharedAttentionFaultCode::CapacityOverflow
    );
    seed.capacity = AttentionCapacity {
        accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
        context_budget_bytes: 100,
        pinned_anchor_bytes: 0,
        current_focus_bytes: 0,
        retrieved_association_bytes: 0,
        recent_stream_bytes: 0,
        reserved_headroom_bytes: 100,
    };
    seed.participants
        .get_mut(&sid("participant:guard"))
        .expect("guard")
        .faculties
        .remove(&FacultyKind::Security);
    assert_eq!(
        new_shared_attention_frame(seed)
            .expect_err("missing gate")
            .code,
        SharedAttentionFaultCode::InvalidFrame
    );
}

#[test]
fn settlement_and_dream_proof_lineage_are_part_of_their_digests() {
    let sealed = sealed_frame();
    let mut missing_settlement_lineage = sealed.clone();
    missing_settlement_lineage
        .settlement_attestation_refs
        .clear();
    assert_eq!(
        validate_shared_attention_frame(&missing_settlement_lineage)
            .expect_err("missing settlement lineage")
            .code,
        SharedAttentionFaultCode::MissingAttestation
    );

    let dream = fork_dream_frame(&sealed, dream_seed(&sealed)).expect("dream");
    let testing = record_dream_evidence(
        &sealed,
        &dream,
        &BTreeSet::from([sid("evidence:dream-test")]),
    )
    .expect("testing dream");
    let verified = review_dream_frame(&sealed, &testing, &gate_dream_reviews(&testing))
        .expect("dream review")
        .successor
        .expect("verified dream");
    let mut missing_review_lineage = verified;
    missing_review_lineage.verification_review_refs.clear();
    assert_eq!(
        validate_dream_frame(&sealed, &missing_review_lineage)
            .expect_err("missing dream review lineage")
            .code,
        SharedAttentionFaultCode::MissingAttestation
    );
}

#[test]
fn dream_can_be_explicitly_discarded_without_changing_reality() {
    let parent = sealed_frame();
    let parent_before = parent.clone();
    let dream = fork_dream_frame(&parent, dream_seed(&parent)).expect("dream");
    let (discarded, receipt) =
        discard_dream_frame(&parent, &dream, "falsifier was observed").expect("discard dream");
    assert_eq!(discarded.status, DreamStatus::Discarded);
    assert_eq!(receipt.predecessor_dream_digest, dream.dream_digest);
    assert_eq!(receipt.discarded_dream_digest, discarded.dream_digest);
    assert_eq!(parent, parent_before);
    assert_eq!(
        project_dream_promotion(
            &parent,
            &discarded,
            sid("delta:discarded"),
            sid("participant:projection"),
            EpistemicStatus::Assumed,
            3,
        )
        .expect_err("discarded promotion")
        .code,
        SharedAttentionFaultCode::DreamBoundary
    );
}

#[test]
fn refiner_compaction_reclaims_headroom_and_allows_rebound_work_to_resume() {
    let base = frame_with_headroom(1);
    let incoming = delta(
        &base,
        "delta:buffered-before-compaction",
        "participant:projection",
        1,
        vec![FrameDeltaOperation::AddProposition {
            proposition: proposition(
                "proposition:after-compaction",
                "This valid update waits until headroom is reclaimed.",
                EpistemicStatus::Inferred,
                None,
            ),
        }],
    );
    let buffered = reconcile_attention_deltas(&base, std::slice::from_ref(&incoming))
        .expect("buffered outcome");
    assert_eq!(buffered.disposition, ReconciliationDisposition::Buffered);
    let base_before = base.clone();

    let compacted = compact_attention_frame(
        &base,
        &compaction(&base, "compaction:reclaim-headroom", "participant:server"),
    )
    .expect("Refiner compaction");
    assert_eq!(base, base_before);
    assert_eq!(compacted.successor.generation, base.generation + 1);
    assert_eq!(compacted.successor.status, SharedFrameStatus::Working);
    assert!(compacted.successor.current_focus_refs.is_empty());
    assert!(compacted.receipt.headroom_after_bytes > compacted.receipt.headroom_before_bytes);
    assert!(
        compacted
            .successor
            .applied_compaction_refs
            .contains(&sid("compaction:reclaim-headroom"))
    );
    assert!(
        compacted
            .successor
            .evidence_refs
            .contains(&sid("evidence:compaction"))
    );

    assert_eq!(
        reconcile_attention_deltas(&compacted.successor, &[incoming])
            .expect_err("old delta remains stale")
            .code,
        SharedAttentionFaultCode::StaleBase
    );
    let rebound = delta(
        &compacted.successor,
        "delta:buffered-before-compaction",
        "participant:projection",
        2,
        vec![FrameDeltaOperation::AddProposition {
            proposition: proposition(
                "proposition:after-compaction",
                "This valid update waits until headroom is reclaimed.",
                EpistemicStatus::Inferred,
                None,
            ),
        }],
    );
    let resumed = reconcile_attention_deltas(&compacted.successor, &[rebound])
        .expect("resumed reconciliation");
    assert_eq!(resumed.disposition, ReconciliationDisposition::Applied);
    assert!(
        resumed
            .successor
            .expect("resumed successor")
            .propositions
            .contains_key(&sid("proposition:after-compaction"))
    );
}

#[test]
fn compaction_requires_refiner_exact_base_evidence_and_monotonic_reduction() {
    let base = frame_with_headroom(1);
    let unauthorized = compaction(&base, "compaction:unauthorized", "participant:guard");
    assert_eq!(
        compact_attention_frame(&base, &unauthorized)
            .expect_err("guard is not Refiner")
            .code,
        SharedAttentionFaultCode::UnauthorizedFaculty
    );

    let mut expanding = compaction(&base, "compaction:expanding", "participant:server");
    expanding.current_focus_bytes_after = base.capacity.current_focus_bytes + 1;
    expanding = finalize_attention_compaction(expanding).expect("resign expansion");
    assert_eq!(
        compact_attention_frame(&base, &expanding)
            .expect_err("compaction expansion")
            .code,
        SharedAttentionFaultCode::InvalidTransition
    );

    let mut no_evidence = compaction(&base, "compaction:no-evidence", "participant:server");
    no_evidence.evidence_refs.clear();
    no_evidence = finalize_attention_compaction(no_evidence).expect("resign no-evidence");
    assert_eq!(
        compact_attention_frame(&base, &no_evidence)
            .expect_err("missing evidence")
            .code,
        SharedAttentionFaultCode::InvalidTransition
    );

    let mut stale = compaction(&base, "compaction:stale", "participant:server");
    stale.base_generation += 1;
    stale = finalize_attention_compaction(stale).expect("resign stale compaction");
    assert_eq!(
        compact_attention_frame(&base, &stale)
            .expect_err("stale compaction")
            .code,
        SharedAttentionFaultCode::StaleBase
    );
}

#[test]
fn shared_tool_dispatch_reaches_all_eleven_closed_operations() {
    let working = frame_with_headroom(1_000_000);
    let validated =
        execute_shared_attention_tool_request(SharedAttentionToolRequest::ValidateFrame {
            frame: working.clone(),
        });
    assert_eq!(validated.status, SharedAttentionToolStatus::Succeeded);
    assert!(matches!(
        validated.result,
        Some(SharedAttentionToolResult::Frame(_))
    ));

    let reconciled = execute_shared_attention_tool_request(SharedAttentionToolRequest::Reconcile {
        base: working.clone(),
        deltas: vec![delta(
            &working,
            "delta:tool-dispatch",
            "participant:guard",
            1,
            vec![FrameDeltaOperation::AttachEvidence {
                evidence_ref: sid("evidence:tool-dispatch"),
            }],
        )],
    });
    assert!(matches!(
        reconciled.result,
        Some(SharedAttentionToolResult::Reconciliation(_))
    ));

    let compacted = execute_shared_attention_tool_request(SharedAttentionToolRequest::Compact {
        base: working.clone(),
        compaction: compaction(&working, "compaction:tool-dispatch", "participant:server"),
    });
    assert!(matches!(
        compacted.result,
        Some(SharedAttentionToolResult::Compaction(_))
    ));

    let prepared = execute_shared_attention_tool_request(SharedAttentionToolRequest::Prepare {
        working: working.clone(),
    });
    let candidate = match prepared.result {
        Some(SharedAttentionToolResult::Preparation(prepared)) => prepared.candidate,
        other => panic!("unexpected preparation result: {other:?}"),
    };
    let settled = execute_shared_attention_tool_request(SharedAttentionToolRequest::Settle {
        attestations: complete_attestations(&candidate),
        candidate,
    });
    let parent = match settled.result {
        Some(SharedAttentionToolResult::Settlement(outcome)) => {
            outcome.sealed_frame.expect("sealed tool frame")
        }
        other => panic!("unexpected settlement result: {other:?}"),
    };

    let forked = execute_shared_attention_tool_request(SharedAttentionToolRequest::ForkDream {
        seed: dream_seed(&parent),
        parent: parent.clone(),
    });
    let dream = match forked.result {
        Some(SharedAttentionToolResult::Dream(dream)) => dream,
        other => panic!("unexpected fork result: {other:?}"),
    };
    let validated_dream =
        execute_shared_attention_tool_request(SharedAttentionToolRequest::ValidateDream {
            parent: parent.clone(),
            dream: dream.clone(),
        });
    assert!(matches!(
        validated_dream.result,
        Some(SharedAttentionToolResult::Dream(_))
    ));

    let testing =
        execute_shared_attention_tool_request(SharedAttentionToolRequest::RecordDreamEvidence {
            parent: parent.clone(),
            dream: dream.clone(),
            evidence_refs: BTreeSet::from([sid("evidence:dream-test")]),
        });
    let testing = match testing.result {
        Some(SharedAttentionToolResult::Dream(testing)) => testing,
        other => panic!("unexpected evidence result: {other:?}"),
    };
    let reviewed = execute_shared_attention_tool_request(SharedAttentionToolRequest::ReviewDream {
        parent: parent.clone(),
        reviews: gate_dream_reviews(&testing),
        dream: testing,
    });
    let verified = match reviewed.result {
        Some(SharedAttentionToolResult::DreamReview(outcome)) => {
            outcome.successor.expect("verified tool dream")
        }
        other => panic!("unexpected review result: {other:?}"),
    };
    let promotion =
        execute_shared_attention_tool_request(SharedAttentionToolRequest::ProjectDreamPromotion {
            parent: parent.clone(),
            dream: verified,
            delta_id: sid("delta:tool-promotion"),
            author_ref: sid("participant:projection"),
            target_status: EpistemicStatus::Assumed,
            logical_time: 2,
        });
    assert!(matches!(
        promotion.result,
        Some(SharedAttentionToolResult::PromotionDelta(_))
    ));

    let discarded =
        execute_shared_attention_tool_request(SharedAttentionToolRequest::DiscardDream {
            parent,
            dream,
            reason: "separate tool discard path".to_owned(),
        });
    assert!(matches!(
        discarded.result,
        Some(SharedAttentionToolResult::DreamDiscard(_))
    ));
}
