use std::collections::BTreeSet;

use cantor_core::{ProtocolRequest, ProtocolResponse, ProtocolStatus, SemanticId};

use crate::{
    CandidateArtifact, CommissionContract, EcosystemMessageEnvelope, ReviewCheck, ReviewCheckKind,
    ReviewDecision, ReviewDisposition, WorkPacket, criteria_by_id,
};

pub fn deterministic_observer_review(
    review_uuid: SemanticId,
    commission: &CommissionContract,
    work_packet: &WorkPacket,
    request: &ProtocolRequest,
    response: &ProtocolResponse,
    candidate: &CandidateArtifact,
    transcript: &[EcosystemMessageEnvelope],
) -> ReviewDecision {
    let criteria = criteria_by_id(work_packet);
    let claimed_ids = &candidate.satisfied_criterion_ids;
    let known_claims = claimed_ids
        .iter()
        .all(|criterion_id| criteria.contains_key(criterion_id));
    let proof_obligation_met = commission.proof_obligation.is_subset(&candidate.proof_refs);
    let evidence_refs = transcript
        .iter()
        .flat_map(|message| message.proof_refs.iter().cloned())
        .collect::<BTreeSet<_>>();
    let evidence_obligation_met = commission.evidence_obligation.is_subset(&evidence_refs);
    let honesty_passed = known_claims && proof_obligation_met && evidence_obligation_met;

    let authority_passed = commission
        .authority_grant
        .contains(&work_packet.authority_grant);
    let security_passed = authority_passed && candidate.requested_effects.is_empty();

    let protocol_passed = response.status == ProtocolStatus::Success
        && cantor_core::verify_protocol_response(request, response).is_ok();

    let required_criteria = work_packet.criterion_ids();
    let acceptance_passed = required_criteria.is_subset(claimed_ids);
    let effect_boundary_passed = candidate.requested_effects.is_empty();

    let checks = vec![
        ReviewCheck {
            check: ReviewCheckKind::Honesty,
            passed: honesty_passed,
            detail: if honesty_passed {
                "criterion claims are known and evidence plus proof obligations are present"
                    .to_owned()
            } else {
                "candidate has unknown claims or does not satisfy evidence and proof obligations"
                    .to_owned()
            },
        },
        ReviewCheck {
            check: ReviewCheckKind::Security,
            passed: security_passed,
            detail: if security_passed {
                "work authority is contained and the candidate requests no effects".to_owned()
            } else {
                "work authority expanded or the candidate requests an effect".to_owned()
            },
        },
        ReviewCheck {
            check: ReviewCheckKind::Protocol,
            passed: protocol_passed,
            detail: if protocol_passed {
                "Cantor response is successful and passes protocol verification".to_owned()
            } else {
                "Cantor response is unsuccessful or fails protocol verification".to_owned()
            },
        },
        ReviewCheck {
            check: ReviewCheckKind::AcceptanceCriteria,
            passed: acceptance_passed,
            detail: if acceptance_passed {
                "candidate claims every work-packet acceptance criterion".to_owned()
            } else {
                "candidate omits at least one work-packet acceptance criterion".to_owned()
            },
        },
        ReviewCheck {
            check: ReviewCheckKind::EffectBoundary,
            passed: effect_boundary_passed,
            detail: if effect_boundary_passed {
                "candidate remains inside the effect-free Phase 1 boundary".to_owned()
            } else {
                "candidate requests an exterior effect forbidden by Phase 1".to_owned()
            },
        },
    ];

    let reasons = checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| check.detail.clone())
        .collect::<Vec<_>>();
    let disposition = if reasons.is_empty() {
        ReviewDisposition::Accept
    } else {
        ReviewDisposition::Revise
    };

    ReviewDecision {
        review_uuid,
        candidate_uuid: candidate.candidate_uuid.clone(),
        disposition,
        checks,
        reasons,
    }
}
