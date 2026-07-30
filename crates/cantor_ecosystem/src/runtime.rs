use std::collections::BTreeSet;

use cantor_core::{ProtocolRequest, ProtocolResponse, SemanticId};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityGrant, CandidateArtifact, CantorAdapter, CodexAdapter, CommissionContract,
    CycleFailure, CycleMetrics, CycleOutcome, CycleProgress, EcosystemFault, EcosystemFaultCode,
    EcosystemMessageEnvelope, ExpectedResponse, FinalDecision, MESSAGE_PROFILE, MOCK_LOOP_PROFILE,
    MessageKind, MessagePayload, MessageTranscript, ParticipantAddress, ReviewDecision,
    ReviewDisposition, WorkPacket, deterministic_observer_review,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleIdentityPlan {
    pub namespace: SemanticId,
}

impl CycleIdentityPlan {
    pub fn new(namespace: impl Into<String>) -> Result<Self, EcosystemFault> {
        let namespace = SemanticId::new(namespace).map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::InvalidIdentity,
                "cycle_identity",
                fault.to_string(),
                Vec::new(),
            )
        })?;
        Ok(Self { namespace })
    }

    fn message_id(&self, kind: MessageKind) -> Result<SemanticId, EcosystemFault> {
        self.derived_id("message", message_label(kind))
    }

    fn idempotency_key(&self, kind: MessageKind) -> Result<SemanticId, EcosystemFault> {
        self.derived_id("idempotency", message_label(kind))
    }

    fn review_id(&self) -> Result<SemanticId, EcosystemFault> {
        self.derived_id("review", "observer")
    }

    fn decision_id(&self) -> Result<SemanticId, EcosystemFault> {
        self.derived_id("decision", "manager")
    }

    fn cantor_proof_ref(&self) -> Result<SemanticId, EcosystemFault> {
        self.derived_id("proof", "cantor_protocol")
    }

    fn derived_id(&self, category: &str, label: &str) -> Result<SemanticId, EcosystemFault> {
        SemanticId::new(format!("{}:{category}:{label}", self.namespace)).map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::InvalidIdentity,
                "cycle_identity",
                fault.to_string(),
                vec![self.namespace.clone()],
            )
        })
    }
}

fn message_label(kind: MessageKind) -> &'static str {
    match kind {
        MessageKind::Commission => "commission",
        MessageKind::Assignment => "assignment",
        MessageKind::CantorQuery => "cantor_query",
        MessageKind::CantorReturn => "cantor_return",
        MessageKind::Candidate => "candidate",
        MessageKind::Review => "review",
        MessageKind::Decision => "decision",
        MessageKind::Fault => "fault",
    }
}

pub fn run_supervised_mock_cycle<Codex, Cantor>(
    commission: CommissionContract,
    work_packet: WorkPacket,
    identities: &CycleIdentityPlan,
    codex: &mut Codex,
    cantor: &mut Cantor,
) -> Result<CycleOutcome, Box<CycleFailure>>
where
    Codex: CodexAdapter,
    Cantor: CantorAdapter,
{
    let mut progress = CycleProgress::Commissioned;
    let mut transcript = MessageTranscript::new(
        commission.clone(),
        work_packet.clone(),
        commission.activated_at_tick,
    )
    .map_err(|fault| failure(progress, fault, None))?;

    let ticks = cycle_ticks(&commission).map_err(|fault| failure(progress, fault, None))?;
    let root = build_envelope(
        identities,
        MessageKind::Commission,
        None,
        &commission.commission_uuid,
        &commission.principal,
        &commission.manager,
        &work_packet.subject,
        &work_packet.frame_digest,
        &commission.authority_grant,
        MessagePayload::Commission(Box::new(commission.clone())),
        commission.evidence_obligation.clone(),
        Some(expected(
            MessageKind::Assignment,
            ticks[1],
            "stop if the manager cannot accept the commission",
        )),
        ticks[0],
        0,
    )
    .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    append(&mut transcript, &commission.manager, root, progress)?;

    progress = CycleProgress::Framed;
    let assignment = build_envelope(
        identities,
        MessageKind::Assignment,
        Some(
            identities
                .message_id(MessageKind::Commission)
                .map_err(|fault| failure(progress, fault, Some(&transcript)))?,
        ),
        &commission.commission_uuid,
        &commission.manager,
        &work_packet.worker,
        &work_packet.subject,
        &work_packet.frame_digest,
        &work_packet.authority_grant,
        MessagePayload::Assignment(Box::new(work_packet.clone())),
        commission.evidence_obligation.clone(),
        Some(expected(
            MessageKind::CantorQuery,
            ticks[2],
            "stop if the worker cannot form the one permitted Cantor query",
        )),
        ticks[1],
        1,
    )
    .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    append(&mut transcript, &work_packet.worker, assignment, progress)?;
    progress = CycleProgress::Assigned;

    let request = codex
        .accept_assignment(&work_packet)
        .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    let query = build_envelope(
        identities,
        MessageKind::CantorQuery,
        Some(
            identities
                .message_id(MessageKind::Assignment)
                .map_err(|fault| failure(progress, fault, Some(&transcript)))?,
        ),
        &commission.commission_uuid,
        &work_packet.worker,
        &work_packet.cantor_participant,
        &work_packet.subject,
        &work_packet.frame_digest,
        &work_packet.authority_grant,
        MessagePayload::CantorQuery(Box::new(request.clone())),
        BTreeSet::new(),
        Some(expected(
            MessageKind::CantorReturn,
            ticks[3],
            "stop if the Cantor participant cannot return verified protocol output",
        )),
        ticks[2],
        2,
    )
    .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    append(
        &mut transcript,
        &work_packet.cantor_participant,
        query,
        progress,
    )?;
    progress = CycleProgress::CantorQueryRequested;

    let response = cantor
        .execute(&request)
        .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    let cantor_proof_ref = identities
        .cantor_proof_ref()
        .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    let cantor_return = build_envelope(
        identities,
        MessageKind::CantorReturn,
        Some(
            identities
                .message_id(MessageKind::CantorQuery)
                .map_err(|fault| failure(progress, fault, Some(&transcript)))?,
        ),
        &commission.commission_uuid,
        &work_packet.cantor_participant,
        &work_packet.worker,
        &work_packet.subject,
        &work_packet.frame_digest,
        &work_packet.authority_grant,
        MessagePayload::CantorReturn(Box::new(response.clone())),
        [cantor_proof_ref].into_iter().collect(),
        Some(expected(
            MessageKind::Candidate,
            ticks[4],
            "stop if the worker cannot form a candidate from the Cantor return",
        )),
        ticks[3],
        2,
    )
    .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    append(
        &mut transcript,
        &work_packet.worker,
        cantor_return,
        progress,
    )?;
    progress = CycleProgress::CantorReturned;

    let candidate = codex
        .accept_cantor_return(&request, &response)
        .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    let candidate_message = build_envelope(
        identities,
        MessageKind::Candidate,
        Some(
            identities
                .message_id(MessageKind::CantorReturn)
                .map_err(|fault| failure(progress, fault, Some(&transcript)))?,
        ),
        &commission.commission_uuid,
        &work_packet.worker,
        &work_packet.observer,
        &work_packet.subject,
        &work_packet.frame_digest,
        &work_packet.authority_grant,
        MessagePayload::Candidate(Box::new(candidate.clone())),
        candidate.proof_refs.clone(),
        Some(expected(
            MessageKind::Review,
            ticks[5],
            "stop if the Observer cannot review the immutable candidate",
        )),
        ticks[4],
        1,
    )
    .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    append(
        &mut transcript,
        &work_packet.observer,
        candidate_message,
        progress,
    )?;
    progress = CycleProgress::CandidateReturned;

    let review_uuid = identities
        .review_id()
        .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    let review = deterministic_observer_review(
        review_uuid,
        &commission,
        &work_packet,
        &request,
        &response,
        &candidate,
        transcript.messages(),
    );
    let review_message = build_envelope(
        identities,
        MessageKind::Review,
        Some(
            identities
                .message_id(MessageKind::Candidate)
                .map_err(|fault| failure(progress, fault, Some(&transcript)))?,
        ),
        &commission.commission_uuid,
        &work_packet.observer,
        &commission.manager,
        &work_packet.subject,
        &work_packet.frame_digest,
        &work_packet.authority_grant,
        MessagePayload::Review(Box::new(review.clone())),
        candidate.proof_refs.clone(),
        Some(expected(
            MessageKind::Decision,
            ticks[6],
            "stop after one manager decision",
        )),
        ticks[5],
        1,
    )
    .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    append(
        &mut transcript,
        &commission.manager,
        review_message,
        progress,
    )?;
    progress = CycleProgress::Reviewed;

    let final_decision = final_decision(identities, &review, &candidate)
        .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    let decision_message = build_envelope(
        identities,
        MessageKind::Decision,
        Some(
            identities
                .message_id(MessageKind::Review)
                .map_err(|fault| failure(progress, fault, Some(&transcript)))?,
        ),
        &commission.commission_uuid,
        &commission.manager,
        &commission.principal,
        &work_packet.subject,
        &work_packet.frame_digest,
        &work_packet.authority_grant,
        MessagePayload::Decision(Box::new(final_decision.clone())),
        [review.review_uuid.clone()].into_iter().collect(),
        None,
        ticks[6],
        0,
    )
    .map_err(|fault| failure(progress, fault, Some(&transcript)))?;
    append(
        &mut transcript,
        &commission.principal,
        decision_message,
        progress,
    )?;

    progress = match final_decision.disposition {
        ReviewDisposition::Accept => CycleProgress::Accepted,
        ReviewDisposition::Revise => CycleProgress::Revise,
        ReviewDisposition::Yield => CycleProgress::Yielded,
        ReviewDisposition::Stop => CycleProgress::Stopped,
        ReviewDisposition::Fault => CycleProgress::Faulted,
    };
    let metrics = CycleMetrics {
        accepted_messages: transcript.messages().len() as u32,
        serialized_bytes: transcript.serialized_bytes(),
        maximum_call_depth_observed: transcript.maximum_call_depth_observed(),
        final_logical_tick: transcript.last_logical_tick().unwrap_or_default(),
        codex_adapter_calls: codex.call_count(),
        cantor_adapter_calls: cantor.call_count(),
    };

    let outcome = CycleOutcome {
        profile: MOCK_LOOP_PROFILE.to_owned(),
        commission_uuid: commission.commission_uuid.clone(),
        work_packet_uuid: work_packet.work_packet_uuid.clone(),
        progress,
        cantor_response: response,
        candidate,
        review,
        final_decision,
        transcript: transcript.into_messages(),
        metrics,
    };
    outcome
        .validate(&commission, &work_packet)
        .map_err(|fault| {
            Box::new(CycleFailure {
                profile: MOCK_LOOP_PROFILE.to_owned(),
                progress,
                fault,
                accepted_prefix: outcome.transcript.clone(),
            })
        })?;
    Ok(outcome)
}

impl CycleOutcome {
    /// Replays and cross-checks a transported outcome as one coherent proof object.
    pub fn validate(
        &self,
        commission: &CommissionContract,
        work_packet: &WorkPacket,
    ) -> Result<(), EcosystemFault> {
        if self.profile != MOCK_LOOP_PROFILE
            || self.commission_uuid != commission.commission_uuid
            || self.work_packet_uuid != work_packet.work_packet_uuid
        {
            return Err(outcome_mismatch(
                "outcome profile or governing identities do not match",
                self,
            ));
        }

        let expected_kinds = [
            MessageKind::Commission,
            MessageKind::Assignment,
            MessageKind::CantorQuery,
            MessageKind::CantorReturn,
            MessageKind::Candidate,
            MessageKind::Review,
            MessageKind::Decision,
        ];
        if self.transcript.len() != expected_kinds.len()
            || !self
                .transcript
                .iter()
                .zip(expected_kinds)
                .all(|(message, expected)| message.message_kind == expected)
        {
            return Err(outcome_mismatch(
                "outcome does not contain the exact seven-message Phase 1 transcript",
                self,
            ));
        }

        let mut replay = MessageTranscript::new(
            commission.clone(),
            work_packet.clone(),
            commission.activated_at_tick,
        )?;
        for envelope in &self.transcript {
            replay.append_for(&envelope.recipient, envelope.clone())?;
        }

        let MessagePayload::Commission(root_commission) = &self.transcript[0].payload else {
            return Err(outcome_mismatch(
                "root transcript payload is not the commission",
                self,
            ));
        };
        let MessagePayload::Assignment(assignment) = &self.transcript[1].payload else {
            return Err(outcome_mismatch(
                "assignment transcript payload is not the work packet",
                self,
            ));
        };
        let MessagePayload::CantorQuery(request) = &self.transcript[2].payload else {
            return Err(outcome_mismatch(
                "query transcript payload is not a Cantor request",
                self,
            ));
        };
        let MessagePayload::CantorReturn(response) = &self.transcript[3].payload else {
            return Err(outcome_mismatch(
                "return transcript payload is not a Cantor response",
                self,
            ));
        };
        let MessagePayload::Candidate(candidate) = &self.transcript[4].payload else {
            return Err(outcome_mismatch(
                "candidate transcript payload is not a candidate",
                self,
            ));
        };
        let MessagePayload::Review(review) = &self.transcript[5].payload else {
            return Err(outcome_mismatch(
                "review transcript payload is not a review",
                self,
            ));
        };
        let MessagePayload::Decision(decision) = &self.transcript[6].payload else {
            return Err(outcome_mismatch(
                "decision transcript payload is not a final decision",
                self,
            ));
        };

        if root_commission.as_ref() != commission
            || assignment.as_ref() != work_packet
            || response.as_ref() != &self.cantor_response
            || candidate.as_ref() != &self.candidate
            || review.as_ref() != &self.review
            || decision.as_ref() != &self.final_decision
        {
            return Err(outcome_mismatch(
                "top-level outcome values differ from their transcript payloads",
                self,
            ));
        }
        cantor_core::verify_protocol_response(request, response).map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::ProtocolFault,
                "outcome_validation",
                fault.message,
                vec![self.commission_uuid.clone()],
            )
        })?;
        if response.status != cantor_core::ProtocolStatus::Success {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::ProtocolFault,
                "outcome_validation",
                "complete Phase 1 outcome contains a non-success Cantor response",
                vec![self.commission_uuid.clone()],
            ));
        }

        candidate.validate()?;
        review.validate()?;
        decision.validate()?;
        let expected_review = deterministic_observer_review(
            review.review_uuid.clone(),
            commission,
            work_packet,
            request,
            response,
            candidate,
            &self.transcript[..5],
        );
        if review.as_ref() != &expected_review {
            return Err(outcome_mismatch(
                "Observer review does not reproduce from the admitted prefix",
                self,
            ));
        }

        let accepted =
            review.disposition == ReviewDisposition::Accept && review.all_checks_passed();
        let expected_progress = match review.disposition {
            ReviewDisposition::Accept if accepted => CycleProgress::Accepted,
            ReviewDisposition::Accept => CycleProgress::Faulted,
            ReviewDisposition::Revise => CycleProgress::Revise,
            ReviewDisposition::Yield => CycleProgress::Yielded,
            ReviewDisposition::Stop => CycleProgress::Stopped,
            ReviewDisposition::Fault => CycleProgress::Faulted,
        };
        let expected_candidate = accepted.then(|| candidate.candidate_uuid.clone());
        if self.progress != expected_progress
            || decision.review_uuid != review.review_uuid
            || decision.disposition != review.disposition
            || decision.accepted_candidate_uuid != expected_candidate
            || decision.reason
                != if accepted {
                    "all mandatory deterministic review checks passed; no effects were requested"
                } else {
                    "candidate was not accepted; no effect was performed"
                }
        {
            return Err(outcome_mismatch(
                "cycle progress or final decision does not follow the Observer review",
                self,
            ));
        }

        let expected_metrics = CycleMetrics {
            accepted_messages: replay.messages().len() as u32,
            serialized_bytes: replay.serialized_bytes(),
            maximum_call_depth_observed: replay.maximum_call_depth_observed(),
            final_logical_tick: replay.last_logical_tick().unwrap_or_default(),
            codex_adapter_calls: 2,
            cantor_adapter_calls: 1,
        };
        if self.metrics != expected_metrics {
            return Err(outcome_mismatch(
                "cycle metrics do not reproduce from the admitted transcript",
                self,
            ));
        }
        Ok(())
    }
}

fn outcome_mismatch(message: &str, outcome: &CycleOutcome) -> EcosystemFault {
    EcosystemFault::new(
        EcosystemFaultCode::OutcomeMismatch,
        "outcome_validation",
        message,
        vec![
            outcome.commission_uuid.clone(),
            outcome.work_packet_uuid.clone(),
        ],
    )
}

fn cycle_ticks(commission: &CommissionContract) -> Result<[u64; 7], EcosystemFault> {
    let mut ticks = [0_u64; 7];
    for (index, tick) in ticks.iter_mut().enumerate() {
        *tick = commission
            .activated_at_tick
            .checked_add(index as u64 + 1)
            .ok_or_else(|| {
                EcosystemFault::new(
                    EcosystemFaultCode::InvalidLifetime,
                    "mock_cycle",
                    "logical tick sequence overflowed",
                    vec![commission.commission_uuid.clone()],
                )
            })?;
    }
    Ok(ticks)
}

#[allow(clippy::too_many_arguments)]
fn build_envelope(
    identities: &CycleIdentityPlan,
    kind: MessageKind,
    causation_uuid: Option<SemanticId>,
    correlation_uuid: &SemanticId,
    sender: &ParticipantAddress,
    recipient: &ParticipantAddress,
    subject: &str,
    frame_digest: &cantor_core::ContentDigest,
    authority_scope: &AuthorityGrant,
    payload: MessagePayload,
    proof_refs: BTreeSet<SemanticId>,
    expected_response: Option<ExpectedResponse>,
    logical_tick: u64,
    call_depth: u16,
) -> Result<EcosystemMessageEnvelope, EcosystemFault> {
    Ok(EcosystemMessageEnvelope {
        profile: MESSAGE_PROFILE.to_owned(),
        message_uuid: identities.message_id(kind)?,
        causation_uuid,
        correlation_uuid: correlation_uuid.clone(),
        sender: sender.clone(),
        recipient: recipient.clone(),
        message_kind: kind,
        subject: subject.to_owned(),
        frame_digest: frame_digest.clone(),
        authority_scope: authority_scope.clone(),
        payload,
        proof_refs,
        expected_response,
        idempotency_key: identities.idempotency_key(kind)?,
        logical_tick,
        call_depth,
    })
}

fn expected(
    message_kind: MessageKind,
    deadline_tick: u64,
    stop_condition: &str,
) -> ExpectedResponse {
    ExpectedResponse {
        message_kind,
        deadline_tick,
        stop_condition: stop_condition.to_owned(),
    }
}

fn final_decision(
    identities: &CycleIdentityPlan,
    review: &ReviewDecision,
    candidate: &CandidateArtifact,
) -> Result<FinalDecision, EcosystemFault> {
    let accepted = review.disposition == ReviewDisposition::Accept && review.all_checks_passed();
    let disposition = if accepted {
        ReviewDisposition::Accept
    } else if review.disposition == ReviewDisposition::Accept {
        ReviewDisposition::Fault
    } else {
        review.disposition
    };
    Ok(FinalDecision {
        decision_uuid: identities.decision_id()?,
        review_uuid: review.review_uuid.clone(),
        disposition,
        accepted_candidate_uuid: accepted.then(|| candidate.candidate_uuid.clone()),
        reason: if accepted {
            "all mandatory deterministic review checks passed; no effects were requested".to_owned()
        } else {
            "candidate was not accepted; no effect was performed".to_owned()
        },
    })
}

fn append(
    transcript: &mut MessageTranscript,
    consumer: &ParticipantAddress,
    envelope: EcosystemMessageEnvelope,
    progress: CycleProgress,
) -> Result<(), Box<CycleFailure>> {
    transcript
        .append_for(consumer, envelope)
        .map_err(|fault| failure(progress, fault, Some(transcript)))
}

fn failure(
    progress: CycleProgress,
    fault: EcosystemFault,
    transcript: Option<&MessageTranscript>,
) -> Box<CycleFailure> {
    Box::new(CycleFailure {
        profile: MOCK_LOOP_PROFILE.to_owned(),
        progress,
        fault,
        accepted_prefix: transcript
            .map(|transcript| transcript.messages().to_vec())
            .unwrap_or_default(),
    })
}

#[allow(dead_code)]
fn _bind_protocol_types(_request: &ProtocolRequest, _response: &ProtocolResponse) {}
