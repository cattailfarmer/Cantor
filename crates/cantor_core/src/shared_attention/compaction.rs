use std::collections::BTreeSet;

use crate::procedure_runtime::empty_sha256;
use crate::{ContentDigest, FacultyKind};

use super::runtime::{
    derive, digest, fault, refresh_frame_digests, require_text, validate_shared_attention_frame,
};
use super::{
    ATTENTION_COMPACTION_PROFILE, AttentionCompaction, AttentionCompactionOutcome,
    AttentionCompactionReceipt, SharedAttentionFault, SharedAttentionFaultCode,
    SharedAttentionFrame, SharedFrameStatus,
};

pub fn finalize_attention_compaction(
    mut compaction: AttentionCompaction,
) -> Result<AttentionCompaction, SharedAttentionFault> {
    compaction.compaction_digest = empty_sha256();
    compaction.compaction_digest = compute_attention_compaction_digest(&compaction)?;
    Ok(compaction)
}

pub fn compute_attention_compaction_digest(
    compaction: &AttentionCompaction,
) -> Result<ContentDigest, SharedAttentionFault> {
    let mut body = compaction.clone();
    body.compaction_digest = empty_sha256();
    digest(&body, "attention compaction")
}

pub fn compact_attention_frame(
    base: &SharedAttentionFrame,
    compaction: &AttentionCompaction,
) -> Result<AttentionCompactionOutcome, SharedAttentionFault> {
    validate_shared_attention_frame(base)?;
    if base.status == SharedFrameStatus::CandidateFrozen {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "a frozen candidate cannot be compacted",
        ));
    }
    if compaction.profile != ATTENTION_COMPACTION_PROFILE
        || compaction.policy_ref != base.policy_ref
        || compaction.base_generation != base.generation
        || compaction.base_frame_digest != base.frame_digest
    {
        return Err(fault(
            SharedAttentionFaultCode::StaleBase,
            "compaction does not bind the exact frame generation digest and policy",
        )
        .with_subject(compaction.compaction_id.clone()));
    }
    if compaction.compaction_digest != compute_attention_compaction_digest(compaction)? {
        return Err(fault(
            SharedAttentionFaultCode::InvalidDigest,
            "compaction digest differs from canonical compaction content",
        )
        .with_subject(compaction.compaction_id.clone()));
    }
    if base
        .applied_compaction_refs
        .contains(&compaction.compaction_id)
    {
        return Err(fault(
            SharedAttentionFaultCode::DuplicateIdentity,
            "compaction identity was already applied to this frame lineage",
        )
        .with_subject(compaction.compaction_id.clone()));
    }
    let actor = base
        .participants
        .get(&compaction.actor_ref)
        .ok_or_else(|| {
            fault(
                SharedAttentionFaultCode::UnknownParticipant,
                "compaction actor is not a frame participant",
            )
            .with_subject(compaction.actor_ref.clone())
        })?;
    if !actor.faculties.contains(&FacultyKind::Refiner) {
        return Err(fault(
            SharedAttentionFaultCode::UnauthorizedFaculty,
            "attention compaction requires a participant with the Refiner faculty",
        )
        .with_subject(compaction.actor_ref.clone()));
    }
    require_text(&compaction.rationale, "compaction rationale")?;
    if compaction.evidence_refs.is_empty() {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "compaction requires at least one evidence reference",
        ));
    }
    if !compaction
        .retained_focus_refs
        .is_subset(&base.current_focus_refs)
    {
        return Err(fault(
            SharedAttentionFaultCode::UnknownReference,
            "compaction retained focus is not a subset of the base focus",
        ));
    }
    if compaction.current_focus_bytes_after > base.capacity.current_focus_bytes
        || compaction.retrieved_association_bytes_after > base.capacity.retrieved_association_bytes
        || compaction.recent_stream_bytes_after > base.capacity.recent_stream_bytes
    {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "compaction cannot increase focus retrieval or recent-stream accounts",
        ));
    }
    let removed_focus_refs = base
        .current_focus_refs
        .difference(&compaction.retained_focus_refs)
        .cloned()
        .collect::<BTreeSet<_>>();
    let has_reduction = !removed_focus_refs.is_empty()
        || compaction.current_focus_bytes_after < base.capacity.current_focus_bytes
        || compaction.retrieved_association_bytes_after < base.capacity.retrieved_association_bytes
        || compaction.recent_stream_bytes_after < base.capacity.recent_stream_bytes;
    if !has_reduction {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "compaction must release focus or reduce at least one removable byte account",
        ));
    }

    let occupied_after = base
        .capacity
        .pinned_anchor_bytes
        .checked_add(compaction.current_focus_bytes_after)
        .and_then(|value| value.checked_add(compaction.retrieved_association_bytes_after))
        .and_then(|value| value.checked_add(compaction.recent_stream_bytes_after))
        .ok_or_else(|| {
            fault(
                SharedAttentionFaultCode::CapacityOverflow,
                "compacted attention byte account overflow",
            )
        })?;
    let headroom_after = base
        .capacity
        .context_budget_bytes
        .checked_sub(occupied_after)
        .ok_or_else(|| {
            fault(
                SharedAttentionFaultCode::CapacityOverflow,
                "compacted regions exceed the unchanged context budget",
            )
        })?;
    if headroom_after <= base.capacity.reserved_headroom_bytes {
        return Err(fault(
            SharedAttentionFaultCode::InvalidTransition,
            "compaction does not increase reserved headroom",
        ));
    }

    let mut successor = base.clone();
    successor.generation = successor.generation.checked_add(1).ok_or_else(|| {
        fault(
            SharedAttentionFaultCode::CapacityOverflow,
            "compaction successor generation overflow",
        )
    })?;
    successor.predecessor_frame_digest = Some(base.frame_digest.clone());
    successor.status = SharedFrameStatus::Working;
    successor.settlement_attestation_refs.clear();
    successor.current_focus_refs = compaction.retained_focus_refs.clone();
    successor.capacity.current_focus_bytes = compaction.current_focus_bytes_after;
    successor.capacity.retrieved_association_bytes = compaction.retrieved_association_bytes_after;
    successor.capacity.recent_stream_bytes = compaction.recent_stream_bytes_after;
    successor.capacity.reserved_headroom_bytes = headroom_after;
    successor
        .evidence_refs
        .extend(compaction.evidence_refs.iter().cloned());
    successor
        .applied_compaction_refs
        .insert(compaction.compaction_id.clone());
    refresh_frame_digests(&mut successor)?;
    validate_shared_attention_frame(&successor)?;

    let seed = digest(
        &(
            &compaction.compaction_id,
            &base.frame_digest,
            &successor.frame_digest,
            &removed_focus_refs,
            base.capacity.reserved_headroom_bytes,
            headroom_after,
        ),
        "attention compaction receipt identity",
    )?;
    let mut receipt = AttentionCompactionReceipt {
        receipt_id: derive("attention:compaction", &seed)?,
        compaction_ref: compaction.compaction_id.clone(),
        predecessor_frame_digest: base.frame_digest.clone(),
        successor_frame_digest: successor.frame_digest.clone(),
        released_focus_refs: removed_focus_refs,
        headroom_before_bytes: base.capacity.reserved_headroom_bytes,
        headroom_after_bytes: headroom_after,
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = digest(&receipt, "attention compaction receipt")?;
    Ok(AttentionCompactionOutcome { successor, receipt })
}
