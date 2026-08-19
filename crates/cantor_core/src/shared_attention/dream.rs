use std::collections::BTreeSet;

use crate::procedure_runtime::empty_sha256;
use crate::{ContentDigest, FacultyKind, SemanticId};

use super::runtime::{
    REQUIRED_GATE_FACULTIES, derive, digest, fault, require_text, validate_shared_attention_frame,
};
use super::{
    ATTENTION_DELTA_PROFILE, AttentionFrameDelta, AttestationDisposition, DREAM_FRAME_PROFILE,
    DREAM_REVIEW_PROFILE, DreamDiscardReceipt, DreamFrame, DreamFrameSeed, DreamReview,
    DreamReviewDisposition, DreamReviewOutcome, DreamReviewReceipt, DreamStatus, EpistemicStatus,
    FrameDeltaOperation, SharedAttentionFault, SharedAttentionFaultCode, SharedAttentionFrame,
    SharedFrameStatus, finalize_attention_delta,
};

pub fn fork_dream_frame(
    parent: &SharedAttentionFrame,
    seed: DreamFrameSeed,
) -> Result<DreamFrame, SharedAttentionFault> {
    validate_shared_attention_frame(parent)?;
    if parent.status != SharedFrameStatus::Sealed {
        return Err(fault(
            SharedAttentionFaultCode::DreamBoundary,
            "a dream can fork only from a sealed reality frame",
        ));
    }
    if seed.parent_frame_digest != parent.frame_digest {
        return Err(fault(
            SharedAttentionFaultCode::StaleBase,
            "dream parent digest is stale or belongs to another frame",
        ));
    }
    let mut dream = DreamFrame {
        profile: DREAM_FRAME_PROFILE.to_owned(),
        dream_id: seed.dream_id,
        parent_frame_id: parent.frame_id.clone(),
        parent_generation: parent.generation,
        parent_frame_digest: parent.frame_digest.clone(),
        purpose: seed.purpose,
        preserved_invariant_refs: seed.preserved_invariant_refs,
        relaxed_assumptions: seed.relaxed_assumptions,
        forbidden_effects: seed.forbidden_effects,
        hypotheses: seed.hypotheses,
        predicted_consequences: seed.predicted_consequences,
        required_evidence_refs: seed.required_evidence_refs,
        observed_evidence_refs: BTreeSet::new(),
        falsification_conditions: seed.falsification_conditions,
        depth: seed.depth,
        maximum_depth: seed.maximum_depth,
        verification_review_refs: BTreeSet::new(),
        status: DreamStatus::Open,
        dream_digest: empty_sha256(),
    };
    dream.dream_digest = compute_dream_digest(&dream)?;
    validate_dream_frame(parent, &dream)?;
    Ok(dream)
}

pub fn validate_dream_frame(
    parent: &SharedAttentionFrame,
    dream: &DreamFrame,
) -> Result<(), SharedAttentionFault> {
    validate_shared_attention_frame(parent)?;
    if parent.status != SharedFrameStatus::Sealed
        || dream.profile != DREAM_FRAME_PROFILE
        || dream.parent_frame_id != parent.frame_id
        || dream.parent_generation != parent.generation
        || dream.parent_frame_digest != parent.frame_digest
    {
        return Err(fault(
            SharedAttentionFaultCode::DreamBoundary,
            "dream does not bind the exact sealed parent frame",
        ));
    }
    require_text(&dream.purpose, "dream purpose")?;
    if dream.depth == 0 || dream.maximum_depth == 0 || dream.depth > dream.maximum_depth {
        return Err(fault(
            SharedAttentionFaultCode::DreamBoundary,
            "dream depth is zero or exceeds its declared maximum",
        ));
    }
    if dream.preserved_invariant_refs.is_empty()
        || dream.forbidden_effects.is_empty()
        || dream.hypotheses.is_empty()
        || dream.required_evidence_refs.is_empty()
        || dream.falsification_conditions.is_empty()
    {
        return Err(fault(
            SharedAttentionFaultCode::DreamBoundary,
            "dream requires invariants forbidden effects hypotheses evidence requirements and falsifiers",
        ));
    }
    for invariant_ref in &dream.preserved_invariant_refs {
        if !parent.propositions.contains_key(invariant_ref)
            && !parent.constraints.contains_key(invariant_ref)
            && !parent.pinned_sop_anchor_refs.contains(invariant_ref)
        {
            return Err(fault(
                SharedAttentionFaultCode::UnknownReference,
                "dream invariant is not present in its sealed parent",
            )
            .with_subject(invariant_ref.clone()));
        }
    }
    for text in dream.relaxed_assumptions.values() {
        require_text(text, "relaxed assumption")?;
    }
    for effect in &dream.forbidden_effects {
        require_text(effect, "forbidden effect")?;
    }
    for (hypothesis_ref, hypothesis) in &dream.hypotheses {
        if hypothesis_ref != &hypothesis.proposition_id
            || hypothesis.epistemic_status != EpistemicStatus::Imagined
            || hypothesis.dream_ref.as_ref() != Some(&dream.dream_id)
        {
            return Err(fault(
                SharedAttentionFaultCode::EpistemicBoundary,
                "dream hypothesis must be imagined and carry exact dream lineage",
            )
            .with_subject(hypothesis_ref.clone()));
        }
        require_text(&hypothesis.text, "dream hypothesis text")?;
    }
    for text in dream.predicted_consequences.values() {
        require_text(text, "predicted consequence")?;
    }
    for condition in &dream.falsification_conditions {
        require_text(condition, "falsification condition")?;
    }
    if dream.status == DreamStatus::Verified
        && !dream
            .required_evidence_refs
            .is_subset(&dream.observed_evidence_refs)
    {
        return Err(fault(
            SharedAttentionFaultCode::DreamBoundary,
            "verified dream lacks required observed evidence",
        ));
    }
    match dream.status {
        DreamStatus::Verified if dream.verification_review_refs.is_empty() => {
            return Err(fault(
                SharedAttentionFaultCode::MissingAttestation,
                "verified dream carries no verification review lineage",
            ));
        }
        DreamStatus::Open | DreamStatus::Testing | DreamStatus::Discarded
            if !dream.verification_review_refs.is_empty() =>
        {
            return Err(fault(
                SharedAttentionFaultCode::DreamBoundary,
                "non-verified dream carries verification review lineage",
            ));
        }
        _ => {}
    }
    if dream.dream_digest != compute_dream_digest(dream)? {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "dream digest differs from canonical branch content",
        ));
    }
    Ok(())
}

pub fn compute_dream_digest(dream: &DreamFrame) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = dream.clone();
    body.dream_digest = empty_sha256();
    digest(&body, "dream frame")
}

pub fn record_dream_evidence(
    parent: &SharedAttentionFrame,
    dream: &DreamFrame,
    evidence_refs: &BTreeSet<SemanticId>,
) -> Result<DreamFrame, SharedAttentionFault> {
    validate_dream_frame(parent, dream)?;
    if !matches!(dream.status, DreamStatus::Open | DreamStatus::Testing) {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "only an open or testing dream may receive evidence",
        ));
    }
    if evidence_refs.is_empty() {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "dream evidence transition requires at least one evidence reference",
        ));
    }
    let mut successor = dream.clone();
    successor
        .observed_evidence_refs
        .extend(evidence_refs.iter().cloned());
    successor.status = DreamStatus::Testing;
    successor.dream_digest = compute_dream_digest(&successor)?;
    validate_dream_frame(parent, &successor)?;
    Ok(successor)
}

pub fn finalize_dream_review(mut review: DreamReview) -> Result<DreamReview, SharedAttentionFault> {
    review.review_digest = empty_sha256();
    review.review_digest = compute_dream_review_digest(&review)?;
    Ok(review)
}

pub fn compute_dream_review_digest(
    review: &DreamReview,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = review.clone();
    body.review_digest = empty_sha256();
    digest(&body, "dream review")
}

pub fn review_dream_frame(
    parent: &SharedAttentionFrame,
    dream: &DreamFrame,
    reviews: &[DreamReview],
) -> Result<DreamReviewOutcome, SharedAttentionFault> {
    validate_dream_frame(parent, dream)?;
    if dream.status != DreamStatus::Testing {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "dream verification requires testing status",
        ));
    }
    let ordered = validate_dream_reviews(parent, dream, reviews)?;
    let review_refs = ordered
        .iter()
        .map(|item| item.review_id.clone())
        .collect::<BTreeSet<_>>();
    let challenge_refs = ordered
        .iter()
        .filter(|item| item.disposition == AttestationDisposition::Challenge)
        .map(|item| item.review_id.clone())
        .collect::<BTreeSet<_>>();
    let defer_refs = ordered
        .iter()
        .filter(|item| item.disposition == AttestationDisposition::Defer)
        .map(|item| item.review_id.clone())
        .collect::<BTreeSet<_>>();
    let acknowledged_faculties = ordered
        .iter()
        .filter(|item| item.disposition == AttestationDisposition::Acknowledge)
        .map(|item| item.faculty)
        .collect::<BTreeSet<_>>();
    let missing_gate_faculties = REQUIRED_GATE_FACULTIES
        .into_iter()
        .filter(|faculty| !acknowledged_faculties.contains(faculty))
        .collect::<BTreeSet<_>>();
    let missing_evidence_refs = dream
        .required_evidence_refs
        .difference(&dream.observed_evidence_refs)
        .cloned()
        .collect::<BTreeSet<_>>();
    let disposition = if !challenge_refs.is_empty() {
        DreamReviewDisposition::RevisionRequired
    } else if !defer_refs.is_empty() {
        DreamReviewDisposition::Deferred
    } else if !missing_gate_faculties.is_empty() || !missing_evidence_refs.is_empty() {
        DreamReviewDisposition::Incomplete
    } else {
        DreamReviewDisposition::Verified
    };
    let successor = if disposition == DreamReviewDisposition::Verified {
        let mut verified = dream.clone();
        verified.status = DreamStatus::Verified;
        verified.verification_review_refs = review_refs.clone();
        verified.dream_digest = compute_dream_digest(&verified)?;
        validate_dream_frame(parent, &verified)?;
        Some(verified)
    } else {
        None
    };
    let receipt = build_dream_review_receipt(
        dream,
        successor.as_ref(),
        disposition,
        review_refs,
        missing_evidence_refs,
        missing_gate_faculties,
        challenge_refs,
        defer_refs,
    )?;
    Ok(DreamReviewOutcome {
        disposition,
        successor,
        receipt,
    })
}

pub fn discard_dream_frame(
    parent: &SharedAttentionFrame,
    dream: &DreamFrame,
    reason: impl Into<String>,
) -> Result<(DreamFrame, DreamDiscardReceipt), SharedAttentionFault> {
    validate_dream_frame(parent, dream)?;
    if !matches!(dream.status, DreamStatus::Open | DreamStatus::Testing) {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "only an open or testing dream may be discarded",
        ));
    }
    let reason = reason.into();
    require_text(&reason, "dream discard reason")?;
    let mut discarded = dream.clone();
    discarded.status = DreamStatus::Discarded;
    discarded.dream_digest = compute_dream_digest(&discarded)?;
    validate_dream_frame(parent, &discarded)?;
    let seed = digest(
        &(&dream.dream_digest, &discarded.dream_digest, &reason),
        "dream discard identity",
    )?;
    let mut receipt = DreamDiscardReceipt {
        receipt_id: derive("attention:dream-discard", &seed)?,
        predecessor_dream_digest: dream.dream_digest.clone(),
        discarded_dream_digest: discarded.dream_digest.clone(),
        reason,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = digest(&receipt, "dream discard receipt")?;
    Ok((discarded, receipt))
}

pub fn project_dream_promotion(
    parent: &SharedAttentionFrame,
    dream: &DreamFrame,
    delta_id: SemanticId,
    author_ref: SemanticId,
    target_status: EpistemicStatus,
    logical_time: u64,
) -> Result<AttentionFrameDelta, SharedAttentionFault> {
    validate_dream_frame(parent, dream)?;
    if dream.status != DreamStatus::Verified {
        return Err(fault(
            SharedAttentionFaultCode::DreamBoundary,
            "only a verified dream can project a promotion delta",
        ));
    }
    if !matches!(
        target_status,
        EpistemicStatus::Assumed | EpistemicStatus::Inferred
    ) {
        return Err(fault(
            SharedAttentionFaultCode::EpistemicBoundary,
            "dream promotion can enter reality only as assumed or inferred",
        ));
    }
    if !parent.participants.contains_key(&author_ref) {
        return Err(fault(
            SharedAttentionFaultCode::UnknownParticipant,
            "dream promotion author is not a frame participant",
        )
        .with_subject(author_ref));
    }
    let mut operations = Vec::with_capacity(dream.hypotheses.len());
    for (hypothesis_ref, hypothesis) in &dream.hypotheses {
        if parent.propositions.contains_key(hypothesis_ref) {
            return Err(fault(
                SharedAttentionFaultCode::DuplicateIdentity,
                "dream promotion would overwrite an existing reality proposition",
            )
            .with_subject(hypothesis_ref.clone()));
        }
        let mut proposition = hypothesis.clone();
        proposition.epistemic_status = target_status;
        proposition
            .evidence_refs
            .extend(dream.observed_evidence_refs.iter().cloned());
        operations.push(FrameDeltaOperation::AddProposition { proposition });
    }
    finalize_attention_delta(AttentionFrameDelta {
        profile: ATTENTION_DELTA_PROFILE.to_owned(),
        delta_id,
        author_ref,
        policy_ref: parent.policy_ref.clone(),
        base_generation: parent.generation,
        base_frame_digest: parent.frame_digest.clone(),
        logical_time,
        operations,
        causal_predecessor_refs: dream
            .verification_review_refs
            .iter()
            .cloned()
            .chain(std::iter::once(dream.dream_id.clone()))
            .collect(),
        delta_digest: empty_sha256(),
    })
}

fn validate_dream_reviews(
    parent: &SharedAttentionFrame,
    dream: &DreamFrame,
    reviews: &[DreamReview],
) -> Result<Vec<DreamReview>, SharedAttentionFault> {
    let mut ordered = reviews.to_vec();
    ordered.sort_by(|left, right| left.review_id.cmp(&right.review_id));
    let mut identities = BTreeSet::new();
    let mut reviewer_faculties = BTreeSet::new();
    for review in &ordered {
        if review.profile != DREAM_REVIEW_PROFILE
            || review.dream_ref != dream.dream_id
            || review.base_dream_digest != dream.dream_digest
        {
            return Err(fault(
                SharedAttentionFaultCode::StaleBase,
                "dream review does not bind the exact branch digest",
            )
            .with_subject(review.review_id.clone()));
        }
        if !identities.insert(review.review_id.clone())
            || !reviewer_faculties.insert((review.reviewer_ref.clone(), review.faculty))
        {
            return Err(fault(
                SharedAttentionFaultCode::DuplicateIdentity,
                "dream review identity or reviewer-faculty pair repeats",
            )
            .with_subject(review.review_id.clone()));
        }
        let participant = parent
            .participants
            .get(&review.reviewer_ref)
            .ok_or_else(|| {
                fault(
                    SharedAttentionFaultCode::UnknownParticipant,
                    "dream reviewer is not a parent-frame participant",
                )
                .with_subject(review.reviewer_ref.clone())
            })?;
        if !participant.faculties.contains(&review.faculty) {
            return Err(fault(
                SharedAttentionFaultCode::UnauthorizedFaculty,
                "dream review faculty is not assigned to its reviewer",
            )
            .with_subject(review.review_id.clone()));
        }
        require_text(&review.rationale, "dream review rationale")?;
        if review.review_digest != compute_dream_review_digest(review)? {
            return Err(fault(
                SharedAttentionFaultCode::InvalidDigest,
                "dream review digest differs from canonical review",
            )
            .with_subject(review.review_id.clone()));
        }
    }
    Ok(ordered)
}

#[allow(clippy::too_many_arguments)]
fn build_dream_review_receipt(
    dream: &DreamFrame,
    successor: Option<&DreamFrame>,
    disposition: DreamReviewDisposition,
    review_refs: BTreeSet<SemanticId>,
    missing_evidence_refs: BTreeSet<SemanticId>,
    missing_gate_faculties: BTreeSet<FacultyKind>,
    challenge_refs: BTreeSet<SemanticId>,
    defer_refs: BTreeSet<SemanticId>,
) -> Result<DreamReviewReceipt, SharedAttentionFault> {
    let successor_dream_digest = successor.map(|value| value.dream_digest.clone());
    let seed = digest(
        &(
            &dream.dream_digest,
            &successor_dream_digest,
            disposition,
            &review_refs,
            &missing_evidence_refs,
            &missing_gate_faculties,
            &challenge_refs,
            &defer_refs,
        ),
        "dream review receipt identity",
    )?;
    let mut receipt = DreamReviewReceipt {
        receipt_id: derive("attention:dream-review", &seed)?,
        predecessor_dream_digest: dream.dream_digest.clone(),
        successor_dream_digest,
        disposition,
        review_refs,
        missing_evidence_refs,
        missing_gate_faculties,
        challenge_refs,
        defer_refs,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = digest(&receipt, "dream review receipt")?;
    Ok(receipt)
}
