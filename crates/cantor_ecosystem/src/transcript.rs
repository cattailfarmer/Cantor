use std::collections::{BTreeMap, BTreeSet};

use cantor_core::SemanticId;

use crate::{
    CommissionContract, EcosystemFault, EcosystemFaultCode, EcosystemMessageEnvelope, MessageKind,
    MessagePayload, ParticipantAddress, ParticipantRole, WorkPacket,
};

/// Append-only, in-memory evidence for one deterministic mock cycle.
#[derive(Clone, Debug)]
pub struct MessageTranscript {
    commission: CommissionContract,
    work_packet: WorkPacket,
    messages: Vec<EcosystemMessageEnvelope>,
    message_positions: BTreeMap<SemanticId, usize>,
    idempotency_keys: BTreeSet<SemanticId>,
    semantic_fingerprints: BTreeSet<String>,
    serialized_bytes: u64,
    maximum_call_depth_observed: u16,
}

impl MessageTranscript {
    pub fn new(
        commission: CommissionContract,
        work_packet: WorkPacket,
        now_tick: u64,
    ) -> Result<Self, EcosystemFault> {
        commission.validate(now_tick)?;
        work_packet.validate(&commission)?;
        Ok(Self {
            commission,
            work_packet,
            messages: Vec::new(),
            message_positions: BTreeMap::new(),
            idempotency_keys: BTreeSet::new(),
            semantic_fingerprints: BTreeSet::new(),
            serialized_bytes: 0,
            maximum_call_depth_observed: 0,
        })
    }

    pub fn append_for(
        &mut self,
        consumer: &ParticipantAddress,
        envelope: EcosystemMessageEnvelope,
    ) -> Result<(), EcosystemFault> {
        envelope.validate_local()?;
        self.validate_consumer(consumer, &envelope)?;
        self.validate_context(&envelope)?;
        self.validate_route(&envelope)?;
        self.validate_replay(&envelope)?;
        self.validate_causation(&envelope)?;
        self.validate_lifetime_and_budget(&envelope)?;

        let encoded = serde_json::to_vec(&envelope).map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::SerializationFault,
                "transcript_append",
                fault.to_string(),
                vec![envelope.message_uuid.clone()],
            )
        })?;
        let next_bytes = self
            .serialized_bytes
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| {
                EcosystemFault::new(
                    EcosystemFaultCode::BudgetExceeded,
                    "transcript_append",
                    "serialized transcript byte count overflowed",
                    vec![envelope.message_uuid.clone()],
                )
            })?;
        let byte_limit = self
            .commission
            .budget
            .maximum_serialized_bytes
            .min(self.work_packet.budget.maximum_serialized_bytes);
        if next_bytes > byte_limit {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BudgetExceeded,
                "transcript_append",
                format!(
                    "serialized transcript would use {next_bytes} bytes, above limit {byte_limit}"
                ),
                vec![envelope.message_uuid.clone()],
            ));
        }

        let fingerprint = envelope.semantic_fingerprint()?.value;
        self.serialized_bytes = next_bytes;
        self.maximum_call_depth_observed =
            self.maximum_call_depth_observed.max(envelope.call_depth);
        self.message_positions
            .insert(envelope.message_uuid.clone(), self.messages.len());
        self.idempotency_keys
            .insert(envelope.idempotency_key.clone());
        self.semantic_fingerprints.insert(fingerprint);
        self.messages.push(envelope);
        Ok(())
    }

    pub fn messages(&self) -> &[EcosystemMessageEnvelope] {
        &self.messages
    }

    pub const fn serialized_bytes(&self) -> u64 {
        self.serialized_bytes
    }

    pub const fn maximum_call_depth_observed(&self) -> u16 {
        self.maximum_call_depth_observed
    }

    pub fn last_logical_tick(&self) -> Option<u64> {
        self.messages.last().map(|message| message.logical_tick)
    }

    pub fn into_messages(self) -> Vec<EcosystemMessageEnvelope> {
        self.messages
    }

    fn validate_consumer(
        &self,
        consumer: &ParticipantAddress,
        envelope: &EcosystemMessageEnvelope,
    ) -> Result<(), EcosystemFault> {
        if &envelope.recipient != consumer {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::WrongRecipient,
                "message_admission",
                "message is not addressed to the consuming participant",
                vec![envelope.message_uuid.clone(), consumer.identity.clone()],
            ));
        }
        if !self.is_known_participant(&envelope.sender)
            || !self.is_known_participant(&envelope.recipient)
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::InvalidParticipant,
                "message_admission",
                "message sender or recipient is outside the commissioned participant set",
                vec![envelope.message_uuid.clone()],
            ));
        }
        Ok(())
    }

    fn validate_context(&self, envelope: &EcosystemMessageEnvelope) -> Result<(), EcosystemFault> {
        let related = vec![envelope.message_uuid.clone()];
        if envelope.correlation_uuid != self.commission.commission_uuid {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::CorrelationMismatch,
                "message_admission",
                "message correlation differs from the active commission",
                related,
            ));
        }
        if envelope.frame_digest != self.work_packet.frame_digest {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::FrameMismatch,
                "message_admission",
                "message frame differs from the active work packet",
                related,
            ));
        }
        if !self
            .commission
            .authority_grant
            .contains(&envelope.authority_scope)
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::AuthorityDenied,
                "message_admission",
                "message authority exceeds the commission",
                related,
            ));
        }
        if !self.messages.is_empty()
            && !self
                .work_packet
                .authority_grant
                .contains(&envelope.authority_scope)
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::AuthorityDenied,
                "message_admission",
                "message authority exceeds the work packet",
                related,
            ));
        }
        if let Some(expected) = &envelope.expected_response
            && expected.deadline_tick > self.commission.expires_at_tick
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::InvalidLifetime,
                "message_admission",
                "expected response deadline exceeds commission expiry",
                related,
            ));
        }
        if self.messages.is_empty() {
            self.validate_root(envelope)?;
        } else {
            if matches!(envelope.message_kind, MessageKind::Commission) {
                return Err(EcosystemFault::new(
                    EcosystemFaultCode::UnexpectedMessage,
                    "message_admission",
                    "a commission message is valid only as the transcript root",
                    related,
                ));
            }
            if let MessagePayload::Assignment(packet) = &envelope.payload {
                packet.validate(&self.commission)?;
                if packet.as_ref() != &self.work_packet {
                    return Err(EcosystemFault::new(
                        EcosystemFaultCode::CorrelationMismatch,
                        "message_admission",
                        "assignment payload differs from the active work packet",
                        related,
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_root(&self, envelope: &EcosystemMessageEnvelope) -> Result<(), EcosystemFault> {
        let valid_payload = match &envelope.payload {
            MessagePayload::Commission(commission) => commission.as_ref() == &self.commission,
            _ => false,
        };
        if envelope.message_kind != MessageKind::Commission
            || envelope.causation_uuid.is_some()
            || envelope.sender != self.commission.principal
            || envelope.recipient != self.commission.manager
            || !valid_payload
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::UnexpectedMessage,
                "message_admission",
                "transcript root must be the exact principal-to-manager commission",
                vec![envelope.message_uuid.clone()],
            ));
        }
        Ok(())
    }

    fn validate_causation(
        &self,
        envelope: &EcosystemMessageEnvelope,
    ) -> Result<(), EcosystemFault> {
        if self.messages.is_empty() {
            return Ok(());
        }
        let Some(causation_uuid) = &envelope.causation_uuid else {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BrokenCausation,
                "message_admission",
                "non-root message has no causal predecessor",
                vec![envelope.message_uuid.clone()],
            ));
        };
        let Some(position) = self.message_positions.get(causation_uuid) else {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BrokenCausation,
                "message_admission",
                "causal predecessor is absent from the accepted transcript",
                vec![envelope.message_uuid.clone(), causation_uuid.clone()],
            ));
        };
        let predecessor = &self.messages[*position];
        if predecessor.correlation_uuid != envelope.correlation_uuid
            || predecessor.recipient != envelope.sender
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BrokenCausation,
                "message_admission",
                "causal predecessor does not hand control to this sender in the same correlation",
                vec![envelope.message_uuid.clone(), causation_uuid.clone()],
            ));
        }
        let Some(expected) = &predecessor.expected_response else {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::UnexpectedMessage,
                "message_admission",
                "causal predecessor declared no permitted response",
                vec![envelope.message_uuid.clone(), causation_uuid.clone()],
            ));
        };
        if expected.message_kind != envelope.message_kind {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::UnexpectedMessage,
                "message_admission",
                "message kind differs from the causal predecessor response contract",
                vec![envelope.message_uuid.clone(), causation_uuid.clone()],
            ));
        }
        if envelope.logical_tick > expected.deadline_tick {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::CommissionExpired,
                "message_admission",
                "message arrived after the causal predecessor response deadline",
                vec![envelope.message_uuid.clone(), causation_uuid.clone()],
            ));
        }
        Ok(())
    }

    fn validate_route(&self, envelope: &EcosystemMessageEnvelope) -> Result<(), EcosystemFault> {
        let expected_route = match envelope.message_kind {
            MessageKind::Commission => (&self.commission.principal, &self.commission.manager),
            MessageKind::Assignment => (&self.commission.manager, &self.work_packet.worker),
            MessageKind::CantorQuery => (
                &self.work_packet.worker,
                &self.work_packet.cantor_participant,
            ),
            MessageKind::CantorReturn => (
                &self.work_packet.cantor_participant,
                &self.work_packet.worker,
            ),
            MessageKind::Candidate => (&self.work_packet.worker, &self.work_packet.observer),
            MessageKind::Review => (&self.work_packet.observer, &self.commission.manager),
            MessageKind::Decision => (&self.commission.manager, &self.commission.principal),
            MessageKind::Fault => {
                return Err(EcosystemFault::new(
                    EcosystemFaultCode::UnexpectedMessage,
                    "message_admission",
                    "Phase 1 returns faults out of band and admits no fault envelope",
                    vec![envelope.message_uuid.clone()],
                ));
            }
        };
        if &envelope.sender != expected_route.0 || &envelope.recipient != expected_route.1 {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::WrongRecipient,
                "message_admission",
                "sender and recipient do not match the fixed Phase 1 route for this message kind",
                vec![envelope.message_uuid.clone()],
            ));
        }
        Ok(())
    }

    fn validate_lifetime_and_budget(
        &self,
        envelope: &EcosystemMessageEnvelope,
    ) -> Result<(), EcosystemFault> {
        let related = vec![envelope.message_uuid.clone()];
        if envelope.logical_tick < self.commission.activated_at_tick
            || envelope.logical_tick > self.commission.expires_at_tick
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::CommissionExpired,
                "message_admission",
                "message logical tick is outside commission lifetime",
                related,
            ));
        }
        if let Some(last_tick) = self.last_logical_tick()
            && envelope.logical_tick <= last_tick
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::NonMonotonicTick,
                "message_admission",
                "message logical tick does not advance the transcript",
                related,
            ));
        }
        let message_limit = self
            .commission
            .budget
            .maximum_messages
            .min(self.work_packet.budget.maximum_messages);
        if self.messages.len() as u32 >= message_limit {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BudgetExceeded,
                "message_admission",
                "message count would exceed the active budget",
                related,
            ));
        }
        let tick_limit = self
            .commission
            .budget
            .maximum_logical_ticks
            .min(self.work_packet.budget.maximum_logical_ticks);
        if envelope
            .logical_tick
            .saturating_sub(self.commission.activated_at_tick)
            > tick_limit
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BudgetExceeded,
                "message_admission",
                "message logical tick exceeds the active budget",
                related,
            ));
        }
        let depth_limit = self
            .commission
            .budget
            .maximum_call_depth
            .min(self.work_packet.budget.maximum_call_depth);
        if envelope.call_depth > depth_limit {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BudgetExceeded,
                "message_admission",
                "message call depth exceeds the active budget",
                related,
            ));
        }
        Ok(())
    }

    fn validate_replay(&self, envelope: &EcosystemMessageEnvelope) -> Result<(), EcosystemFault> {
        if self.message_positions.contains_key(&envelope.message_uuid) {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::MessageReplay,
                "message_admission",
                "message identity was already accepted",
                vec![envelope.message_uuid.clone()],
            ));
        }
        if self.idempotency_keys.contains(&envelope.idempotency_key) {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::IdempotencyReplay,
                "message_admission",
                "idempotency identity was already accepted",
                vec![
                    envelope.message_uuid.clone(),
                    envelope.idempotency_key.clone(),
                ],
            ));
        }
        let fingerprint = envelope.semantic_fingerprint()?.value;
        if self.semantic_fingerprints.contains(&fingerprint) {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::SemanticCycle,
                "message_admission",
                "equivalent participant, subject, frame, kind, and payload state already exists",
                vec![envelope.message_uuid.clone()],
            ));
        }
        Ok(())
    }

    fn is_known_participant(&self, participant: &ParticipantAddress) -> bool {
        match participant.role {
            ParticipantRole::Principal => participant == &self.commission.principal,
            ParticipantRole::Manager => participant == &self.commission.manager,
            ParticipantRole::CodexThread => participant == &self.work_packet.worker,
            ParticipantRole::CantorParticipant => {
                participant == &self.work_packet.cantor_participant
            }
            ParticipantRole::Observer => participant == &self.work_packet.observer,
            ParticipantRole::EffectBroker => false,
        }
    }
}
