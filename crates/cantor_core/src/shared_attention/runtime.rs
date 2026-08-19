use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::procedure_runtime::{derived_id, digest_serialized, empty_sha256};
use crate::{ContentDigest, FacultyKind, SemanticId};

use super::{
    ATTENTION_BYTE_PROXY_PROFILE, ATTENTION_DELTA_PROFILE, AttentionCapacity, AttentionFrameDelta,
    AttestationDisposition, BackpressureReceipt, CandidatePreparationReceipt, EpistemicStatus,
    FRAME_ATTESTATION_PROFILE, FrameAttestation, FrameDeltaOperation, FrameReconciliation,
    FrameTransitionReceipt, FramedProposition, PreparedAttentionCandidate,
    ReconciliationDisposition, SHARED_ATTENTION_PROFILE, SettlementDisposition, SettlementOutcome,
    SettlementReceipt, SharedAttentionFault, SharedAttentionFaultCode, SharedAttentionFrame,
    SharedAttentionFrameSeed, SharedFrameStatus,
};

pub(super) const REQUIRED_GATE_FACULTIES: [FacultyKind; 3] = [
    FacultyKind::Observer,
    FacultyKind::Honesty,
    FacultyKind::Security,
];

pub fn new_shared_attention_frame(
    seed: SharedAttentionFrameSeed,
) -> Result<SharedAttentionFrame, SharedAttentionFault> {
    let mut frame = SharedAttentionFrame {
        profile: SHARED_ATTENTION_PROFILE.to_owned(),
        frame_id: seed.frame_id,
        generation: 0,
        predecessor_frame_digest: None,
        purpose: seed.purpose,
        policy_ref: seed.policy_ref,
        participants: seed.participants,
        propositions: seed.propositions,
        constraints: seed.constraints,
        pinned_sop_anchor_refs: seed.pinned_sop_anchor_refs,
        evidence_refs: seed.evidence_refs,
        challenges: BTreeMap::new(),
        current_focus_refs: seed.current_focus_refs,
        capacity: seed.capacity,
        applied_delta_refs: BTreeSet::new(),
        applied_compaction_refs: BTreeSet::new(),
        settlement_attestation_refs: BTreeSet::new(),
        status: SharedFrameStatus::Working,
        semantic_digest: empty_sha256(),
        frame_digest: empty_sha256(),
    };
    refresh_frame_digests(&mut frame)?;
    validate_shared_attention_frame(&frame)?;
    Ok(frame)
}

pub fn validate_shared_attention_frame(
    frame: &SharedAttentionFrame,
) -> Result<(), SharedAttentionFault> {
    if frame.profile != SHARED_ATTENTION_PROFILE {
        return Err(fault(
            SharedAttentionFaultCode::InvalidFrame,
            "shared attention frame profile is not supported",
        ));
    }
    require_text(&frame.purpose, "frame purpose")?;
    validate_capacity(&frame.capacity)?;
    if frame.participants.is_empty() || !frame.participants.values().any(|item| item.required) {
        return Err(fault(
            SharedAttentionFaultCode::InvalidFrame,
            "frame requires participants and at least one required participant",
        ));
    }
    let mut declared_faculties = BTreeSet::new();
    for (participant_ref, participant) in &frame.participants {
        if participant_ref != &participant.participant_id || participant.faculties.is_empty() {
            return Err(fault(
                SharedAttentionFaultCode::InvalidFrame,
                "participant key, identity, or faculty declaration is invalid",
            )
            .with_subject(participant_ref.clone()));
        }
        declared_faculties.extend(participant.faculties.iter().copied());
    }
    for faculty in REQUIRED_GATE_FACULTIES {
        if !declared_faculties.contains(&faculty) {
            return Err(fault(
                SharedAttentionFaultCode::InvalidFrame,
                format!("frame omits mandatory {faculty:?} gate faculty"),
            ));
        }
    }
    for (proposition_ref, proposition) in &frame.propositions {
        validate_reality_proposition(proposition_ref, proposition)?;
    }
    for (constraint_ref, text) in &frame.constraints {
        require_text(text, "constraint text")
            .map_err(|error| error.with_subject(constraint_ref.clone()))?;
    }
    for (challenge_ref, text) in &frame.challenges {
        require_text(text, "challenge text")
            .map_err(|error| error.with_subject(challenge_ref.clone()))?;
    }
    for focus_ref in &frame.current_focus_refs {
        if !frame.propositions.contains_key(focus_ref) {
            return Err(fault(
                SharedAttentionFaultCode::UnknownReference,
                "current focus refers to an unknown proposition",
            )
            .with_subject(focus_ref.clone()));
        }
    }
    if frame.generation == 0 && frame.predecessor_frame_digest.is_some()
        || frame.generation > 0 && frame.predecessor_frame_digest.is_none()
    {
        return Err(fault(
            SharedAttentionFaultCode::InvalidFrame,
            "frame predecessor presence does not match generation",
        ));
    }
    if matches!(
        frame.status,
        SharedFrameStatus::CandidateFrozen | SharedFrameStatus::Sealed
    ) && !frame.challenges.is_empty()
    {
        return Err(fault(
            SharedAttentionFaultCode::UnresolvedChallenge,
            "frozen or sealed frame retains an unresolved challenge",
        ));
    }
    match frame.status {
        SharedFrameStatus::Sealed if frame.settlement_attestation_refs.is_empty() => {
            return Err(fault(
                SharedAttentionFaultCode::MissingAttestation,
                "sealed frame carries no settlement attestation lineage",
            ));
        }
        SharedFrameStatus::Working | SharedFrameStatus::CandidateFrozen
            if !frame.settlement_attestation_refs.is_empty() =>
        {
            return Err(fault(
                SharedAttentionFaultCode::InvalidFrame,
                "non-sealed frame carries settlement attestation lineage",
            ));
        }
        _ => {}
    }
    let expected_semantic = compute_frame_semantic_digest(frame)?;
    if frame.semantic_digest != expected_semantic {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "frame semantic digest differs from canonical content",
        ));
    }
    let expected_frame = compute_frame_digest(frame)?;
    if frame.frame_digest != expected_frame {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "frame digest differs from canonical frame",
        ));
    }
    Ok(())
}

pub fn compute_frame_semantic_digest(
    frame: &SharedAttentionFrame,
) -> Result<ContentDigest, SharedAttentionFault> {
    digest(
        &(
            &frame.profile,
            &frame.frame_id,
            &frame.purpose,
            &frame.policy_ref,
            &frame.participants,
            &frame.propositions,
            &frame.constraints,
            &frame.pinned_sop_anchor_refs,
            &frame.evidence_refs,
            &frame.challenges,
            &frame.current_focus_refs,
        ),
        "shared attention frame semantic content",
    )
}

pub fn compute_frame_digest(
    frame: &SharedAttentionFrame,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = frame.clone();
    body.frame_digest = empty_sha256();
    digest(&body, "shared attention frame")
}

pub fn finalize_attention_delta(
    mut delta: AttentionFrameDelta,
) -> Result<AttentionFrameDelta, SharedAttentionFault> {
    delta.delta_digest = empty_sha256();
    delta.delta_digest = compute_delta_digest(&delta)?;
    Ok(delta)
}

pub fn compute_delta_digest(
    delta: &AttentionFrameDelta,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = delta.clone();
    body.delta_digest = empty_sha256();
    digest(&body, "attention frame delta")
}

pub fn reconcile_attention_deltas(
    base: &SharedAttentionFrame,
    deltas: &[AttentionFrameDelta],
) -> Result<FrameReconciliation, SharedAttentionFault> {
    validate_shared_attention_frame(base)?;
    if base.status == SharedFrameStatus::CandidateFrozen {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "a frozen candidate cannot accept deltas",
        ));
    }
    if deltas.is_empty() {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "reconciliation requires at least one delta",
        ));
    }

    let mut ordered = deltas.to_vec();
    ordered.sort_by(|left, right| left.delta_id.cmp(&right.delta_id));
    validate_delta_batch(base, &ordered)?;
    for delta in &ordered {
        for operation in &delta.operations {
            validate_operation_against_base(base, operation)?;
        }
    }
    let novelty_bytes = canonical_bytes(&ordered, "attention delta batch")?;
    if novelty_bytes > base.capacity.reserved_headroom_bytes {
        let receipt = build_backpressure_receipt(base, &ordered, novelty_bytes)?;
        return Ok(FrameReconciliation {
            disposition: ReconciliationDisposition::Buffered,
            base_frame_digest: base.frame_digest.clone(),
            successor: None,
            transition_receipt: None,
            backpressure_receipt: Some(receipt),
        });
    }

    let mut successor = base.clone();
    successor.status = SharedFrameStatus::Working;
    successor.settlement_attestation_refs.clear();
    successor.generation = successor.generation.checked_add(1).ok_or_else(|| {
        fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "frame generation overflow",
        )
    })?;
    successor.predecessor_frame_digest = Some(base.frame_digest.clone());
    for delta in &ordered {
        for operation in &delta.operations {
            apply_operation(&mut successor, operation)?;
        }
        successor.applied_delta_refs.insert(delta.delta_id.clone());
    }
    successor.capacity.recent_stream_bytes = successor
        .capacity
        .recent_stream_bytes
        .checked_add(novelty_bytes)
        .ok_or_else(|| {
            fault(
                SharedAttentionFaultCode::CapacityOverflow,
                "recent stream byte account overflow",
            )
        })?;
    successor.capacity.reserved_headroom_bytes -= novelty_bytes;
    refresh_frame_digests(&mut successor)?;
    validate_shared_attention_frame(&successor)?;

    let applied_delta_refs = ordered
        .iter()
        .map(|delta| delta.delta_id.clone())
        .collect::<BTreeSet<_>>();
    let transition_receipt = build_transition_receipt(
        &base.frame_digest,
        &successor.frame_digest,
        applied_delta_refs,
        novelty_bytes,
    )?;
    Ok(FrameReconciliation {
        disposition: ReconciliationDisposition::Applied,
        base_frame_digest: base.frame_digest.clone(),
        successor: Some(successor),
        transition_receipt: Some(transition_receipt),
        backpressure_receipt: None,
    })
}

pub fn prepare_attention_candidate(
    working: &SharedAttentionFrame,
) -> Result<PreparedAttentionCandidate, SharedAttentionFault> {
    validate_shared_attention_frame(working)?;
    if working.status != SharedFrameStatus::Working {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "only a working frame can be prepared as a candidate",
        ));
    }
    if !working.challenges.is_empty() {
        return Err(fault(
            SharedAttentionFaultCode::UnresolvedChallenge,
            "frame cannot freeze while challenges remain unresolved",
        ));
    }
    let mut candidate = working.clone();
    candidate.status = SharedFrameStatus::CandidateFrozen;
    candidate.generation = candidate.generation.checked_add(1).ok_or_else(|| {
        fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "candidate generation overflow",
        )
    })?;
    candidate.predecessor_frame_digest = Some(working.frame_digest.clone());
    refresh_frame_digests(&mut candidate)?;
    validate_shared_attention_frame(&candidate)?;

    let seed = digest(
        &(
            &working.frame_digest,
            &candidate.frame_digest,
            candidate.generation,
        ),
        "candidate preparation identity",
    )?;
    let mut receipt = CandidatePreparationReceipt {
        receipt_id: derive("attention:candidate-preparation", &seed)?,
        working_frame_digest: working.frame_digest.clone(),
        candidate_frame_digest: candidate.frame_digest.clone(),
        candidate_generation: candidate.generation,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = digest(&receipt, "candidate preparation receipt")?;
    Ok(PreparedAttentionCandidate { candidate, receipt })
}

pub fn finalize_frame_attestation(
    mut attestation: FrameAttestation,
) -> Result<FrameAttestation, SharedAttentionFault> {
    attestation.attestation_digest = empty_sha256();
    attestation.attestation_digest = compute_frame_attestation_digest(&attestation)?;
    Ok(attestation)
}

pub fn compute_frame_attestation_digest(
    attestation: &FrameAttestation,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = attestation.clone();
    body.attestation_digest = empty_sha256();
    digest(&body, "frame attestation")
}

pub fn settle_attention_candidate(
    candidate: &SharedAttentionFrame,
    attestations: &[FrameAttestation],
) -> Result<SettlementOutcome, SharedAttentionFault> {
    validate_shared_attention_frame(candidate)?;
    if candidate.status != SharedFrameStatus::CandidateFrozen {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "settlement requires a frozen candidate",
        ));
    }
    let ordered = validate_frame_attestations(candidate, attestations)?;
    let attestation_refs = ordered
        .iter()
        .map(|item| item.attestation_id.clone())
        .collect::<BTreeSet<_>>();
    let challenge_refs = ordered
        .iter()
        .filter(|item| item.disposition == AttestationDisposition::Challenge)
        .map(|item| item.attestation_id.clone())
        .collect::<BTreeSet<_>>();
    let defer_refs = ordered
        .iter()
        .filter(|item| item.disposition == AttestationDisposition::Defer)
        .map(|item| item.attestation_id.clone())
        .collect::<BTreeSet<_>>();
    let acknowledged_participants = ordered
        .iter()
        .filter(|item| item.disposition == AttestationDisposition::Acknowledge)
        .map(|item| item.participant_ref.clone())
        .collect::<BTreeSet<_>>();
    let acknowledged_faculties = ordered
        .iter()
        .filter(|item| item.disposition == AttestationDisposition::Acknowledge)
        .map(|item| item.faculty)
        .collect::<BTreeSet<_>>();
    let required_participants = candidate
        .participants
        .values()
        .filter(|item| item.required)
        .map(|item| item.participant_id.clone())
        .collect::<BTreeSet<_>>();
    let missing_participant_refs = required_participants
        .difference(&acknowledged_participants)
        .cloned()
        .collect::<BTreeSet<_>>();
    let missing_gate_faculties = REQUIRED_GATE_FACULTIES
        .into_iter()
        .filter(|faculty| !acknowledged_faculties.contains(faculty))
        .collect::<BTreeSet<_>>();

    let disposition = if !challenge_refs.is_empty() {
        SettlementDisposition::RevisionRequired
    } else if !defer_refs.is_empty() {
        SettlementDisposition::Deferred
    } else if !missing_participant_refs.is_empty() || !missing_gate_faculties.is_empty() {
        SettlementDisposition::Incomplete
    } else {
        SettlementDisposition::Sealed
    };

    let sealed_frame = if disposition == SettlementDisposition::Sealed {
        let mut sealed = candidate.clone();
        sealed.status = SharedFrameStatus::Sealed;
        sealed.settlement_attestation_refs = attestation_refs.clone();
        sealed.generation = sealed.generation.checked_add(1).ok_or_else(|| {
            fault(
                SharedAttentionFaultCode::CapacityOverflow,
                "sealed frame generation overflow",
            )
        })?;
        sealed.predecessor_frame_digest = Some(candidate.frame_digest.clone());
        refresh_frame_digests(&mut sealed)?;
        validate_shared_attention_frame(&sealed)?;
        Some(sealed)
    } else {
        None
    };
    let receipt = build_settlement_receipt(
        candidate,
        sealed_frame.as_ref(),
        disposition,
        attestation_refs,
        missing_participant_refs,
        missing_gate_faculties,
        challenge_refs,
        defer_refs,
    )?;
    Ok(SettlementOutcome {
        disposition,
        sealed_frame,
        receipt,
    })
}

pub(super) fn refresh_frame_digests(
    frame: &mut SharedAttentionFrame,
) -> Result<(), SharedAttentionFault> {
    frame.semantic_digest = compute_frame_semantic_digest(frame)?;
    frame.frame_digest = empty_sha256();
    frame.frame_digest = compute_frame_digest(frame)?;
    Ok(())
}

fn validate_capacity(capacity: &AttentionCapacity) -> Result<(), SharedAttentionFault> {
    if capacity.accounting_profile != ATTENTION_BYTE_PROXY_PROFILE
        || capacity.context_budget_bytes == 0
    {
        return Err(fault(
            SharedAttentionFaultCode::InvalidFrame,
            "attention capacity profile is unsupported or context budget is zero",
        ));
    }
    let used = capacity
        .pinned_anchor_bytes
        .checked_add(capacity.current_focus_bytes)
        .and_then(|value| value.checked_add(capacity.retrieved_association_bytes))
        .and_then(|value| value.checked_add(capacity.recent_stream_bytes))
        .and_then(|value| value.checked_add(capacity.reserved_headroom_bytes))
        .ok_or_else(|| {
            fault(
                SharedAttentionFaultCode::CapacityOverflow,
                "attention region byte account overflow",
            )
        })?;
    if used > capacity.context_budget_bytes {
        return Err(fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "attention regions and reserved headroom exceed context budget",
        ));
    }
    Ok(())
}

fn validate_reality_proposition(
    proposition_ref: &SemanticId,
    proposition: &FramedProposition,
) -> Result<(), SharedAttentionFault> {
    if proposition_ref != &proposition.proposition_id {
        return Err(fault(
            SharedAttentionFaultCode::InvalidFrame,
            "proposition map key differs from proposition identity",
        )
        .with_subject(proposition_ref.clone()));
    }
    require_text(&proposition.text, "proposition text")?;
    if proposition.epistemic_status == EpistemicStatus::Imagined {
        return Err(fault(
            SharedAttentionFaultCode::EpistemicBoundary,
            "imagined propositions belong in a DreamFrame, not a reality frame",
        )
        .with_subject(proposition_ref.clone()));
    }
    Ok(())
}

fn validate_delta_batch(
    base: &SharedAttentionFrame,
    ordered: &[AttentionFrameDelta],
) -> Result<(), SharedAttentionFault> {
    let mut delta_ids = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for delta in ordered {
        if delta.profile != ATTENTION_DELTA_PROFILE {
            return Err(fault(
                SharedAttentionFaultCode::InvalidFrame,
                "attention delta profile is not supported",
            ));
        }
        if !delta_ids.insert(delta.delta_id.clone()) {
            return Err(fault(
                SharedAttentionFaultCode::DuplicateIdentity,
                "delta identity repeats in one reconciliation batch",
            )
            .with_subject(delta.delta_id.clone()));
        }
        if base.applied_delta_refs.contains(&delta.delta_id) {
            return Err(fault(
                SharedAttentionFaultCode::DuplicateIdentity,
                "delta identity was already applied to this frame lineage",
            )
            .with_subject(delta.delta_id.clone()));
        }
        if !base.participants.contains_key(&delta.author_ref) {
            return Err(fault(
                SharedAttentionFaultCode::UnknownParticipant,
                "delta author is not a declared frame participant",
            )
            .with_subject(delta.author_ref.clone()));
        }
        if delta.policy_ref != base.policy_ref
            || delta.base_generation != base.generation
            || delta.base_frame_digest != base.frame_digest
        {
            return Err(fault(
                SharedAttentionFaultCode::StaleBase,
                "delta does not bind the exact frame generation digest and policy",
            )
            .with_subject(delta.delta_id.clone()));
        }
        if delta.operations.is_empty() {
            return Err(fault(
                SharedAttentionFaultCode::InvalidTransition,
                "delta contains no operation",
            )
            .with_subject(delta.delta_id.clone()));
        }
        if delta.delta_digest != compute_delta_digest(delta)? {
            return Err(fault(
                SharedAttentionFaultCode::InvalidDigest,
                "delta digest differs from canonical delta content",
            )
            .with_subject(delta.delta_id.clone()));
        }
        for operation in &delta.operations {
            for target in operation_targets(operation) {
                if !targets.insert(target) {
                    return Err(fault(
                        SharedAttentionFaultCode::ConflictingMutation,
                        "multiple operations mutate the same semantic target in one batch",
                    )
                    .with_subject(delta.delta_id.clone()));
                }
            }
        }
    }
    Ok(())
}

fn operation_targets(operation: &FrameDeltaOperation) -> Vec<String> {
    match operation {
        FrameDeltaOperation::AddProposition { proposition }
        | FrameDeltaOperation::ReplaceProposition { proposition } => {
            vec![format!("proposition:{}", proposition.proposition_id)]
        }
        FrameDeltaOperation::RemoveProposition { proposition_ref } => vec![
            format!("proposition:{proposition_ref}"),
            format!("focus:{proposition_ref}"),
        ],
        FrameDeltaOperation::AddConstraint { constraint_id, .. } => {
            vec![format!("constraint:{constraint_id}")]
        }
        FrameDeltaOperation::RemoveConstraint { constraint_ref } => {
            vec![format!("constraint:{constraint_ref}")]
        }
        FrameDeltaOperation::PinAnchor { anchor_ref }
        | FrameDeltaOperation::ReleaseAnchor { anchor_ref } => {
            vec![format!("anchor:{anchor_ref}")]
        }
        FrameDeltaOperation::AttachEvidence { evidence_ref } => {
            vec![format!("evidence:{evidence_ref}")]
        }
        FrameDeltaOperation::RaiseChallenge { challenge_id, .. } => {
            vec![format!("challenge:{challenge_id}")]
        }
        FrameDeltaOperation::ResolveChallenge { challenge_ref } => {
            vec![format!("challenge:{challenge_ref}")]
        }
        FrameDeltaOperation::SetFocus { proposition_ref }
        | FrameDeltaOperation::ReleaseFocus { proposition_ref } => {
            vec![format!("focus:{proposition_ref}")]
        }
    }
}

fn validate_operation_against_base(
    base: &SharedAttentionFrame,
    operation: &FrameDeltaOperation,
) -> Result<(), SharedAttentionFault> {
    match operation {
        FrameDeltaOperation::AddProposition { proposition } => {
            validate_reality_proposition(&proposition.proposition_id, proposition)?;
            if base.propositions.contains_key(&proposition.proposition_id) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "ADD_PROPOSITION target already exists in the base frame",
                )
                .with_subject(proposition.proposition_id.clone()));
            }
        }
        FrameDeltaOperation::ReplaceProposition { proposition } => {
            validate_reality_proposition(&proposition.proposition_id, proposition)?;
            if !base.propositions.contains_key(&proposition.proposition_id) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "REPLACE_PROPOSITION target does not exist in the base frame",
                )
                .with_subject(proposition.proposition_id.clone()));
            }
        }
        FrameDeltaOperation::RemoveProposition { proposition_ref } => {
            if !base.propositions.contains_key(proposition_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "REMOVE_PROPOSITION target does not exist in the base frame",
                )
                .with_subject(proposition_ref.clone()));
            }
        }
        FrameDeltaOperation::AddConstraint {
            constraint_id,
            text,
        } => {
            require_text(text, "constraint text")?;
            if base.constraints.contains_key(constraint_id) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "ADD_CONSTRAINT target already exists in the base frame",
                )
                .with_subject(constraint_id.clone()));
            }
        }
        FrameDeltaOperation::RemoveConstraint { constraint_ref } => {
            if !base.constraints.contains_key(constraint_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "REMOVE_CONSTRAINT target does not exist in the base frame",
                )
                .with_subject(constraint_ref.clone()));
            }
        }
        FrameDeltaOperation::PinAnchor { anchor_ref } => {
            if base.pinned_sop_anchor_refs.contains(anchor_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "PIN_ANCHOR target is already pinned in the base frame",
                )
                .with_subject(anchor_ref.clone()));
            }
        }
        FrameDeltaOperation::ReleaseAnchor { anchor_ref } => {
            if !base.pinned_sop_anchor_refs.contains(anchor_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "RELEASE_ANCHOR target is not pinned in the base frame",
                )
                .with_subject(anchor_ref.clone()));
            }
        }
        FrameDeltaOperation::AttachEvidence { evidence_ref } => {
            if base.evidence_refs.contains(evidence_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "ATTACH_EVIDENCE target already exists in the base frame",
                )
                .with_subject(evidence_ref.clone()));
            }
        }
        FrameDeltaOperation::RaiseChallenge { challenge_id, text } => {
            require_text(text, "challenge text")?;
            if base.challenges.contains_key(challenge_id) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "RAISE_CHALLENGE target already exists in the base frame",
                )
                .with_subject(challenge_id.clone()));
            }
        }
        FrameDeltaOperation::ResolveChallenge { challenge_ref } => {
            if !base.challenges.contains_key(challenge_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "RESOLVE_CHALLENGE target does not exist in the base frame",
                )
                .with_subject(challenge_ref.clone()));
            }
        }
        FrameDeltaOperation::SetFocus { proposition_ref } => {
            if !base.propositions.contains_key(proposition_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "SET_FOCUS target does not exist in the base frame",
                )
                .with_subject(proposition_ref.clone()));
            }
            if base.current_focus_refs.contains(proposition_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "SET_FOCUS target is already focused in the base frame",
                )
                .with_subject(proposition_ref.clone()));
            }
        }
        FrameDeltaOperation::ReleaseFocus { proposition_ref } => {
            if !base.current_focus_refs.contains(proposition_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "RELEASE_FOCUS target is not focused in the base frame",
                )
                .with_subject(proposition_ref.clone()));
            }
        }
    }
    Ok(())
}

fn apply_operation(
    frame: &mut SharedAttentionFrame,
    operation: &FrameDeltaOperation,
) -> Result<(), SharedAttentionFault> {
    match operation {
        FrameDeltaOperation::AddProposition { proposition } => {
            validate_reality_proposition(&proposition.proposition_id, proposition)?;
            if frame
                .propositions
                .insert(proposition.proposition_id.clone(), proposition.clone())
                .is_some()
            {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "ADD_PROPOSITION target already exists",
                )
                .with_subject(proposition.proposition_id.clone()));
            }
        }
        FrameDeltaOperation::ReplaceProposition { proposition } => {
            validate_reality_proposition(&proposition.proposition_id, proposition)?;
            if !frame.propositions.contains_key(&proposition.proposition_id) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "REPLACE_PROPOSITION target does not exist",
                )
                .with_subject(proposition.proposition_id.clone()));
            }
            frame
                .propositions
                .insert(proposition.proposition_id.clone(), proposition.clone());
        }
        FrameDeltaOperation::RemoveProposition { proposition_ref } => {
            if frame.propositions.remove(proposition_ref).is_none() {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "REMOVE_PROPOSITION target does not exist",
                )
                .with_subject(proposition_ref.clone()));
            }
            frame.current_focus_refs.remove(proposition_ref);
        }
        FrameDeltaOperation::AddConstraint {
            constraint_id,
            text,
        } => {
            require_text(text, "constraint text")?;
            if frame
                .constraints
                .insert(constraint_id.clone(), text.clone())
                .is_some()
            {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "ADD_CONSTRAINT target already exists",
                )
                .with_subject(constraint_id.clone()));
            }
        }
        FrameDeltaOperation::RemoveConstraint { constraint_ref } => {
            if frame.constraints.remove(constraint_ref).is_none() {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "REMOVE_CONSTRAINT target does not exist",
                )
                .with_subject(constraint_ref.clone()));
            }
        }
        FrameDeltaOperation::PinAnchor { anchor_ref } => {
            if !frame.pinned_sop_anchor_refs.insert(anchor_ref.clone()) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "PIN_ANCHOR target is already pinned",
                )
                .with_subject(anchor_ref.clone()));
            }
        }
        FrameDeltaOperation::ReleaseAnchor { anchor_ref } => {
            if !frame.pinned_sop_anchor_refs.remove(anchor_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "RELEASE_ANCHOR target is not pinned",
                )
                .with_subject(anchor_ref.clone()));
            }
        }
        FrameDeltaOperation::AttachEvidence { evidence_ref } => {
            if !frame.evidence_refs.insert(evidence_ref.clone()) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "ATTACH_EVIDENCE target already exists",
                )
                .with_subject(evidence_ref.clone()));
            }
        }
        FrameDeltaOperation::RaiseChallenge { challenge_id, text } => {
            require_text(text, "challenge text")?;
            if frame
                .challenges
                .insert(challenge_id.clone(), text.clone())
                .is_some()
            {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "RAISE_CHALLENGE target already exists",
                )
                .with_subject(challenge_id.clone()));
            }
        }
        FrameDeltaOperation::ResolveChallenge { challenge_ref } => {
            if frame.challenges.remove(challenge_ref).is_none() {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "RESOLVE_CHALLENGE target does not exist",
                )
                .with_subject(challenge_ref.clone()));
            }
        }
        FrameDeltaOperation::SetFocus { proposition_ref } => {
            if !frame.propositions.contains_key(proposition_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "SET_FOCUS target proposition does not exist",
                )
                .with_subject(proposition_ref.clone()));
            }
            if !frame.current_focus_refs.insert(proposition_ref.clone()) {
                return Err(fault(
                    SharedAttentionFaultCode::DuplicateIdentity,
                    "SET_FOCUS target is already focused",
                )
                .with_subject(proposition_ref.clone()));
            }
        }
        FrameDeltaOperation::ReleaseFocus { proposition_ref } => {
            if !frame.current_focus_refs.remove(proposition_ref) {
                return Err(fault(
                    SharedAttentionFaultCode::UnknownReference,
                    "RELEASE_FOCUS target is not focused",
                )
                .with_subject(proposition_ref.clone()));
            }
        }
    }
    Ok(())
}

fn validate_frame_attestations(
    candidate: &SharedAttentionFrame,
    attestations: &[FrameAttestation],
) -> Result<Vec<FrameAttestation>, SharedAttentionFault> {
    let mut ordered = attestations.to_vec();
    ordered.sort_by(|left, right| left.attestation_id.cmp(&right.attestation_id));
    let mut identities = BTreeSet::new();
    let mut participant_faculties = BTreeSet::new();
    for attestation in &ordered {
        if attestation.profile != FRAME_ATTESTATION_PROFILE
            || attestation.candidate_generation != candidate.generation
            || attestation.candidate_frame_digest != candidate.frame_digest
        {
            return Err(fault(
                SharedAttentionFaultCode::StaleBase,
                "attestation does not bind the exact frozen candidate",
            )
            .with_subject(attestation.attestation_id.clone()));
        }
        if !identities.insert(attestation.attestation_id.clone())
            || !participant_faculties
                .insert((attestation.participant_ref.clone(), attestation.faculty))
        {
            return Err(fault(
                SharedAttentionFaultCode::DuplicateIdentity,
                "attestation identity or participant-faculty pair repeats",
            )
            .with_subject(attestation.attestation_id.clone()));
        }
        let participant = candidate
            .participants
            .get(&attestation.participant_ref)
            .ok_or_else(|| {
                fault(
                    SharedAttentionFaultCode::UnknownParticipant,
                    "attestation participant is not declared in the frame",
                )
                .with_subject(attestation.participant_ref.clone())
            })?;
        if !participant.faculties.contains(&attestation.faculty) {
            return Err(fault(
                SharedAttentionFaultCode::UnauthorizedFaculty,
                "attestation faculty is not assigned to its participant",
            )
            .with_subject(attestation.attestation_id.clone()));
        }
        require_text(&attestation.rationale, "attestation rationale")?;
        if attestation.attestation_digest != compute_frame_attestation_digest(attestation)? {
            return Err(fault(
                SharedAttentionFaultCode::InvalidDigest,
                "attestation digest differs from canonical attestation",
            )
            .with_subject(attestation.attestation_id.clone()));
        }
    }
    Ok(ordered)
}

fn build_backpressure_receipt(
    base: &SharedAttentionFrame,
    ordered: &[AttentionFrameDelta],
    novelty_bytes: u64,
) -> Result<BackpressureReceipt, SharedAttentionFault> {
    let buffered_delta_refs = ordered
        .iter()
        .map(|delta| delta.delta_id.clone())
        .collect::<BTreeSet<_>>();
    let seed = digest(
        &(
            &base.frame_digest,
            novelty_bytes,
            base.capacity.reserved_headroom_bytes,
            &buffered_delta_refs,
        ),
        "backpressure identity",
    )?;
    let mut receipt = BackpressureReceipt {
        receipt_id: derive("attention:backpressure", &seed)?,
        base_frame_digest: base.frame_digest.clone(),
        required_novelty_bytes: novelty_bytes,
        available_headroom_bytes: base.capacity.reserved_headroom_bytes,
        accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
        buffered_delta_refs,
        recovery_actions: vec![
            "freeze_frame".to_owned(),
            "preserve_event_log".to_owned(),
            "classify_novelty".to_owned(),
            "cluster_novelty".to_owned(),
            "prioritize_authority_identity_security".to_owned(),
            "split_subordinate_frames".to_owned(),
            "compact_working_set".to_owned(),
            "reconcile_then_resume".to_owned(),
        ],
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = digest(&receipt, "backpressure receipt")?;
    Ok(receipt)
}

fn build_transition_receipt(
    predecessor_frame_digest: &ContentDigest,
    successor_frame_digest: &ContentDigest,
    applied_delta_refs: BTreeSet<SemanticId>,
    novelty_bytes: u64,
) -> Result<FrameTransitionReceipt, SharedAttentionFault> {
    let seed = digest(
        &(
            predecessor_frame_digest,
            successor_frame_digest,
            &applied_delta_refs,
            novelty_bytes,
        ),
        "frame transition identity",
    )?;
    let mut receipt = FrameTransitionReceipt {
        transition_id: derive("attention:frame-transition", &seed)?,
        predecessor_frame_digest: predecessor_frame_digest.clone(),
        successor_frame_digest: successor_frame_digest.clone(),
        applied_delta_refs,
        novelty_bytes,
        transition_digest: empty_sha256(),
    };
    receipt.transition_digest = digest(&receipt, "frame transition receipt")?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
fn build_settlement_receipt(
    candidate: &SharedAttentionFrame,
    sealed: Option<&SharedAttentionFrame>,
    disposition: SettlementDisposition,
    attestation_refs: BTreeSet<SemanticId>,
    missing_participant_refs: BTreeSet<SemanticId>,
    missing_gate_faculties: BTreeSet<FacultyKind>,
    challenge_refs: BTreeSet<SemanticId>,
    defer_refs: BTreeSet<SemanticId>,
) -> Result<SettlementReceipt, SharedAttentionFault> {
    let sealed_frame_digest = sealed.map(|frame| frame.frame_digest.clone());
    let seed = digest(
        &(
            &candidate.frame_digest,
            &sealed_frame_digest,
            disposition,
            &attestation_refs,
            &missing_participant_refs,
            &missing_gate_faculties,
            &challenge_refs,
            &defer_refs,
        ),
        "settlement identity",
    )?;
    let mut receipt = SettlementReceipt {
        receipt_id: derive("attention:settlement", &seed)?,
        candidate_frame_digest: candidate.frame_digest.clone(),
        sealed_frame_digest,
        disposition,
        attestation_refs,
        missing_participant_refs,
        missing_gate_faculties,
        challenge_refs,
        defer_refs,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = digest(&receipt, "settlement receipt")?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn require_text(value: &str, label: &str) -> Result<(), SharedAttentionFault> {
    if value.trim().is_empty() {
        Err(fault(
            SharedAttentionFaultCode::InvalidFrame,
            format!("{label} must not be empty"),
        ))
    } else {
        Ok(())
    }
}

fn canonical_bytes<T: Serialize>(value: &T, label: &str) -> Result<u64, SharedAttentionFault> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        fault(
            SharedAttentionFaultCode::MachineForm,
            format!("{label} serialization failed: {error}"),
        )
    })?;
    u64::try_from(bytes.len()).map_err(|_| {
        fault(
            SharedAttentionFaultCode::CapacityOverflow,
            format!("{label} byte length does not fit u64"),
        )
    })
}

pub(super) fn digest<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<ContentDigest, SharedAttentionFault> {
    digest_serialized(value, label)
        .map_err(|error| fault(SharedAttentionFaultCode::MachineForm, error.to_string()))
}

pub(super) fn derive(
    prefix: &str,
    value: &ContentDigest,
) -> Result<SemanticId, SharedAttentionFault> {
    derived_id(prefix, value)
        .map_err(|error| fault(SharedAttentionFaultCode::MachineForm, error.to_string()))
}

pub(super) fn fault(
    code: SharedAttentionFaultCode,
    message: impl Into<String>,
) -> SharedAttentionFault {
    SharedAttentionFault::new(code, message)
}
