use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cantor_core::{ContentDigest, ProtocolRequest, ProtocolResponse, SemanticId, sha256_digest};
use serde::{Deserialize, Serialize};

use crate::{COMMISSION_PROFILE, MESSAGE_PROFILE, WORK_PACKET_PROFILE};

const MAX_TEXT_BYTES: usize = 4_096;
const MAX_FAULT_MESSAGE_CHARS: usize = 512;
const MAX_COLLECTION_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Principal,
    Manager,
    CodexThread,
    CantorParticipant,
    Observer,
    EffectBroker,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParticipantAddress {
    pub role: ParticipantRole,
    pub identity: SemanticId,
}

impl ParticipantAddress {
    pub fn new(role: ParticipantRole, identity: impl Into<String>) -> Result<Self, EcosystemFault> {
        let identity = SemanticId::new(identity).map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::InvalidIdentity,
                "participant",
                fault.to_string(),
                Vec::new(),
            )
        })?;
        Ok(Self { role, identity })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityGrant {
    pub projects: BTreeSet<String>,
    pub semantic_operations: BTreeSet<String>,
    pub tool_capabilities: BTreeSet<String>,
    pub data_scopes: BTreeSet<String>,
    pub effect_classes: BTreeSet<String>,
}

impl AuthorityGrant {
    pub fn contains(&self, requested: &Self) -> bool {
        requested.projects.is_subset(&self.projects)
            && requested
                .semantic_operations
                .is_subset(&self.semantic_operations)
            && requested
                .tool_capabilities
                .is_subset(&self.tool_capabilities)
            && requested.data_scopes.is_subset(&self.data_scopes)
            && requested.effect_classes.is_subset(&self.effect_classes)
    }

    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            projects: intersection(&self.projects, &other.projects),
            semantic_operations: intersection(
                &self.semantic_operations,
                &other.semantic_operations,
            ),
            tool_capabilities: intersection(&self.tool_capabilities, &other.tool_capabilities),
            data_scopes: intersection(&self.data_scopes, &other.data_scopes),
            effect_classes: intersection(&self.effect_classes, &other.effect_classes),
        }
    }

    pub fn validate(&self, stage: &str) -> Result<(), EcosystemFault> {
        for (name, values) in [
            ("projects", &self.projects),
            ("semantic_operations", &self.semantic_operations),
            ("tool_capabilities", &self.tool_capabilities),
            ("data_scopes", &self.data_scopes),
            ("effect_classes", &self.effect_classes),
        ] {
            validate_collection_len(name, values.len(), stage)?;
            for value in values {
                validate_text(name, value, stage)?;
            }
        }
        Ok(())
    }
}

fn intersection(values: &BTreeSet<String>, other: &BTreeSet<String>) -> BTreeSet<String> {
    values.intersection(other).cloned().collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemBudget {
    pub maximum_messages: u32,
    pub maximum_serialized_bytes: u64,
    pub maximum_call_depth: u16,
    pub maximum_logical_ticks: u64,
}

impl EcosystemBudget {
    pub const fn contains(self, requested: Self) -> bool {
        requested.maximum_messages <= self.maximum_messages
            && requested.maximum_serialized_bytes <= self.maximum_serialized_bytes
            && requested.maximum_call_depth <= self.maximum_call_depth
            && requested.maximum_logical_ticks <= self.maximum_logical_ticks
    }

    pub fn validate(self, stage: &str) -> Result<(), EcosystemFault> {
        if self.maximum_messages == 0
            || self.maximum_serialized_bytes == 0
            || self.maximum_logical_ticks == 0
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::InvalidBudget,
                stage,
                "message, byte, and logical-tick budgets must be nonzero",
                Vec::new(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommissionLifecycle {
    Active,
    Revoked,
    Expired,
    Completed,
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCheckKind {
    Honesty,
    Security,
    Protocol,
    AcceptanceCriteria,
    EffectBoundary,
}

pub fn mandatory_review_checks() -> BTreeSet<ReviewCheckKind> {
    [
        ReviewCheckKind::Honesty,
        ReviewCheckKind::Security,
        ReviewCheckKind::Protocol,
        ReviewCheckKind::AcceptanceCriteria,
        ReviewCheckKind::EffectBoundary,
    ]
    .into_iter()
    .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommissionContract {
    pub profile: String,
    pub commission_uuid: SemanticId,
    pub principal: ParticipantAddress,
    pub manager: ParticipantAddress,
    pub purpose: String,
    pub requested_result: String,
    pub authority_grant: AuthorityGrant,
    pub required_review_checks: BTreeSet<ReviewCheckKind>,
    pub evidence_obligation: BTreeSet<SemanticId>,
    pub proof_obligation: BTreeSet<SemanticId>,
    pub budget: EcosystemBudget,
    pub activated_at_tick: u64,
    pub expires_at_tick: u64,
    pub lifecycle: CommissionLifecycle,
}

impl CommissionContract {
    pub fn validate(&self, now_tick: u64) -> Result<(), EcosystemFault> {
        let related = vec![self.commission_uuid.clone()];
        if self.profile != COMMISSION_PROFILE {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::UnsupportedProfile,
                "commission",
                "unsupported commission profile",
                related,
            ));
        }
        if self.principal.role != ParticipantRole::Principal
            || self.manager.role != ParticipantRole::Manager
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::InvalidParticipant,
                "commission",
                "commission principal and manager roles are invalid",
                related,
            ));
        }
        validate_text("purpose", &self.purpose, "commission")?;
        validate_text("requested_result", &self.requested_result, "commission")?;
        self.authority_grant.validate("commission")?;
        if !self.authority_grant.effect_classes.is_empty() {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::AuthorityDenied,
                "commission",
                "the Phase 1 commission cannot grant exterior effect authority",
                related,
            ));
        }
        self.budget.validate("commission")?;
        if !mandatory_review_checks().is_subset(&self.required_review_checks) {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::MissingReviewCheck,
                "commission",
                "commission omits a mandatory deterministic review check",
                related,
            ));
        }
        validate_collection_len(
            "required review checks",
            self.required_review_checks.len(),
            "commission",
        )?;
        validate_collection_len(
            "evidence obligations",
            self.evidence_obligation.len(),
            "commission",
        )?;
        validate_collection_len(
            "proof obligations",
            self.proof_obligation.len(),
            "commission",
        )?;
        if self.evidence_obligation.is_empty() || self.proof_obligation.is_empty() {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::MissingProof,
                "commission",
                "commission requires nonempty evidence and proof obligations",
                related,
            ));
        }
        if self.expires_at_tick <= self.activated_at_tick {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::InvalidLifetime,
                "commission",
                "commission expiry must follow activation",
                related,
            ));
        }
        if self.lifecycle != CommissionLifecycle::Active {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::CommissionInactive,
                "commission",
                "commission is not active",
                related,
            ));
        }
        if now_tick < self.activated_at_tick || now_tick > self.expires_at_tick {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::CommissionExpired,
                "commission",
                "logical time is outside the active commission lifetime",
                related,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceCriterion {
    pub criterion_id: SemanticId,
    pub description: String,
}

impl AcceptanceCriterion {
    fn validate(&self) -> Result<(), EcosystemFault> {
        validate_text(
            "acceptance criterion description",
            &self.description,
            "work_packet",
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkPacket {
    pub profile: String,
    pub work_packet_uuid: SemanticId,
    pub commission_uuid: SemanticId,
    pub worker: ParticipantAddress,
    pub cantor_participant: ParticipantAddress,
    pub observer: ParticipantAddress,
    pub subject: String,
    pub purpose: String,
    pub requested_result: String,
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    pub authority_grant: AuthorityGrant,
    pub frame_digest: ContentDigest,
    pub budget: EcosystemBudget,
}

impl WorkPacket {
    pub fn validate(&self, commission: &CommissionContract) -> Result<(), EcosystemFault> {
        let related = vec![
            commission.commission_uuid.clone(),
            self.work_packet_uuid.clone(),
        ];
        if self.profile != WORK_PACKET_PROFILE {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::UnsupportedProfile,
                "work_packet",
                "unsupported work-packet profile",
                related,
            ));
        }
        if self.commission_uuid != commission.commission_uuid {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::CorrelationMismatch,
                "work_packet",
                "work packet is bound to a different commission",
                related,
            ));
        }
        if self.worker.role != ParticipantRole::CodexThread
            || self.cantor_participant.role != ParticipantRole::CantorParticipant
            || self.observer.role != ParticipantRole::Observer
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::InvalidParticipant,
                "work_packet",
                "work packet participant roles are invalid",
                related,
            ));
        }
        validate_text("subject", &self.subject, "work_packet")?;
        validate_text("purpose", &self.purpose, "work_packet")?;
        validate_text("requested_result", &self.requested_result, "work_packet")?;
        if self.acceptance_criteria.is_empty() {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::MissingCriterion,
                "work_packet",
                "work packet requires at least one acceptance criterion",
                related,
            ));
        }
        validate_collection_len(
            "acceptance criteria",
            self.acceptance_criteria.len(),
            "work_packet",
        )?;
        let mut criterion_ids = BTreeSet::new();
        for criterion in &self.acceptance_criteria {
            criterion.validate()?;
            if !criterion_ids.insert(&criterion.criterion_id) {
                return Err(EcosystemFault::new(
                    EcosystemFaultCode::DuplicateIdentity,
                    "work_packet",
                    "work packet repeats an acceptance criterion identity",
                    related,
                ));
            }
        }
        self.authority_grant.validate("work_packet")?;
        if !commission.authority_grant.contains(&self.authority_grant) {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::AuthorityDenied,
                "work_packet",
                "work-packet authority exceeds the commission",
                related,
            ));
        }
        self.budget.validate("work_packet")?;
        if !commission.budget.contains(self.budget) {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::BudgetExceeded,
                "work_packet",
                "work-packet budget exceeds the commission",
                related,
            ));
        }
        validate_sha256(&self.frame_digest, "work_packet", related)
    }

    pub fn criterion_ids(&self) -> BTreeSet<SemanticId> {
        self.acceptance_criteria
            .iter()
            .map(|criterion| criterion.criterion_id.clone())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateArtifact {
    pub candidate_uuid: SemanticId,
    pub content_digest: ContentDigest,
    pub summary: String,
    pub satisfied_criterion_ids: BTreeSet<SemanticId>,
    pub proof_refs: BTreeSet<SemanticId>,
    pub requested_effects: BTreeSet<String>,
}

impl CandidateArtifact {
    pub fn validate(&self) -> Result<(), EcosystemFault> {
        validate_sha256(
            &self.content_digest,
            "candidate",
            vec![self.candidate_uuid.clone()],
        )?;
        validate_text("candidate summary", &self.summary, "candidate")?;
        validate_collection_len(
            "candidate criterion claims",
            self.satisfied_criterion_ids.len(),
            "candidate",
        )?;
        validate_collection_len(
            "candidate proof references",
            self.proof_refs.len(),
            "candidate",
        )?;
        validate_collection_len(
            "candidate requested effects",
            self.requested_effects.len(),
            "candidate",
        )?;
        for effect in &self.requested_effects {
            validate_text("requested effect", effect, "candidate")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCheck {
    pub check: ReviewCheckKind,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDisposition {
    Accept,
    Revise,
    Yield,
    Stop,
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDecision {
    pub review_uuid: SemanticId,
    pub candidate_uuid: SemanticId,
    pub disposition: ReviewDisposition,
    pub checks: Vec<ReviewCheck>,
    pub reasons: Vec<String>,
}

impl ReviewDecision {
    pub fn validate(&self) -> Result<(), EcosystemFault> {
        let related = vec![self.review_uuid.clone(), self.candidate_uuid.clone()];
        let required = mandatory_review_checks();
        if self.checks.len() != required.len() {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::MissingReviewCheck,
                "review",
                "review must contain each mandatory check exactly once",
                related,
            ));
        }
        let mut seen = BTreeSet::new();
        for check in &self.checks {
            validate_text("review check detail", &check.detail, "review")?;
            if !seen.insert(check.check) {
                return Err(EcosystemFault::new(
                    EcosystemFaultCode::DuplicateIdentity,
                    "review",
                    "review repeats a mandatory check",
                    vec![self.review_uuid.clone()],
                ));
            }
        }
        if seen != required {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::MissingReviewCheck,
                "review",
                "review does not contain the exact mandatory check set",
                vec![self.review_uuid.clone()],
            ));
        }
        validate_collection_len("review reasons", self.reasons.len(), "review")?;
        for reason in &self.reasons {
            validate_text("review reason", reason, "review")?;
        }
        let all_passed = self.checks.iter().all(|check| check.passed);
        if (self.disposition == ReviewDisposition::Accept
            && (!all_passed || !self.reasons.is_empty()))
            || (self.disposition != ReviewDisposition::Accept
                && !all_passed
                && self.reasons.is_empty())
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::ReviewRejected,
                "review",
                "review disposition, check results, and reasons are inconsistent",
                vec![self.review_uuid.clone()],
            ));
        }
        Ok(())
    }

    pub fn all_checks_passed(&self) -> bool {
        self.validate().is_ok()
            && self.disposition == ReviewDisposition::Accept
            && self.checks.iter().all(|check| check.passed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalDecision {
    pub decision_uuid: SemanticId,
    pub review_uuid: SemanticId,
    pub disposition: ReviewDisposition,
    pub accepted_candidate_uuid: Option<SemanticId>,
    pub reason: String,
}

impl FinalDecision {
    pub fn validate(&self) -> Result<(), EcosystemFault> {
        validate_text("decision reason", &self.reason, "decision")?;
        if (self.disposition == ReviewDisposition::Accept) != self.accepted_candidate_uuid.is_some()
        {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::ReviewRejected,
                "decision",
                "only an accepting decision may identify an accepted candidate",
                vec![self.decision_uuid.clone(), self.review_uuid.clone()],
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Commission,
    Assignment,
    CantorQuery,
    CantorReturn,
    Candidate,
    Review,
    Decision,
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "payload_kind", content = "value", rename_all = "snake_case")]
pub enum MessagePayload {
    Commission(Box<CommissionContract>),
    Assignment(Box<WorkPacket>),
    CantorQuery(Box<ProtocolRequest>),
    CantorReturn(Box<ProtocolResponse>),
    Candidate(Box<CandidateArtifact>),
    Review(Box<ReviewDecision>),
    Decision(Box<FinalDecision>),
    Fault(Box<EcosystemFault>),
}

impl MessagePayload {
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::Commission(_) => MessageKind::Commission,
            Self::Assignment(_) => MessageKind::Assignment,
            Self::CantorQuery(_) => MessageKind::CantorQuery,
            Self::CantorReturn(_) => MessageKind::CantorReturn,
            Self::Candidate(_) => MessageKind::Candidate,
            Self::Review(_) => MessageKind::Review,
            Self::Decision(_) => MessageKind::Decision,
            Self::Fault(_) => MessageKind::Fault,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedResponse {
    pub message_kind: MessageKind,
    pub deadline_tick: u64,
    pub stop_condition: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemMessageEnvelope {
    pub profile: String,
    pub message_uuid: SemanticId,
    pub causation_uuid: Option<SemanticId>,
    pub correlation_uuid: SemanticId,
    pub sender: ParticipantAddress,
    pub recipient: ParticipantAddress,
    pub message_kind: MessageKind,
    pub subject: String,
    pub frame_digest: ContentDigest,
    pub authority_scope: AuthorityGrant,
    pub payload: MessagePayload,
    pub proof_refs: BTreeSet<SemanticId>,
    pub expected_response: Option<ExpectedResponse>,
    pub idempotency_key: SemanticId,
    pub logical_tick: u64,
    pub call_depth: u16,
}

impl EcosystemMessageEnvelope {
    pub fn validate_local(&self) -> Result<(), EcosystemFault> {
        let related = vec![self.message_uuid.clone()];
        if self.profile != MESSAGE_PROFILE {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::UnsupportedProfile,
                "message",
                "unsupported ecosystem message profile",
                related,
            ));
        }
        if self.message_kind != self.payload.kind() {
            return Err(EcosystemFault::new(
                EcosystemFaultCode::PayloadKindMismatch,
                "message",
                "message kind does not match its typed payload",
                related,
            ));
        }
        validate_text("message subject", &self.subject, "message")?;
        self.authority_scope.validate("message")?;
        validate_sha256(&self.frame_digest, "message", related.clone())?;
        validate_collection_len("message proof references", self.proof_refs.len(), "message")?;
        if let Some(expected) = &self.expected_response {
            validate_text(
                "expected response stop condition",
                &expected.stop_condition,
                "message",
            )?;
            if expected.deadline_tick <= self.logical_tick {
                return Err(EcosystemFault::new(
                    EcosystemFaultCode::InvalidLifetime,
                    "message",
                    "expected-response deadline must follow the message tick",
                    related,
                ));
            }
            if permitted_response(self.message_kind) != Some(expected.message_kind) {
                return Err(EcosystemFault::new(
                    EcosystemFaultCode::UnexpectedMessage,
                    "message",
                    "expected response kind is not permitted after this message kind",
                    related,
                ));
            }
        }
        match &self.payload {
            MessagePayload::Commission(commission) => commission.validate(self.logical_tick),
            MessagePayload::Assignment(packet) => {
                validate_text("work packet subject", &packet.subject, "message")
            }
            MessagePayload::Candidate(candidate) => candidate.validate(),
            MessagePayload::Review(review) => review.validate(),
            MessagePayload::Decision(decision) => decision.validate(),
            MessagePayload::CantorQuery(_) | MessagePayload::CantorReturn(_) => Ok(()),
            MessagePayload::Fault(fault) => fault.validate(),
        }
    }

    pub fn semantic_fingerprint(&self) -> Result<ContentDigest, EcosystemFault> {
        sha256_digest(&(
            self.message_kind,
            &self.sender,
            &self.recipient,
            &self.subject,
            &self.frame_digest,
            &self.payload,
        ))
        .map_err(|fault| {
            EcosystemFault::new(
                EcosystemFaultCode::SerializationFault,
                "message_fingerprint",
                fault.to_string(),
                vec![self.message_uuid.clone()],
            )
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleProgress {
    Commissioned,
    Framed,
    Assigned,
    CantorQueryRequested,
    CantorReturned,
    CandidateReturned,
    Reviewed,
    Accepted,
    Revise,
    Yielded,
    Stopped,
    Faulted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleMetrics {
    pub accepted_messages: u32,
    pub serialized_bytes: u64,
    pub maximum_call_depth_observed: u16,
    pub final_logical_tick: u64,
    pub codex_adapter_calls: u32,
    pub cantor_adapter_calls: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleOutcome {
    pub profile: String,
    pub commission_uuid: SemanticId,
    pub work_packet_uuid: SemanticId,
    pub progress: CycleProgress,
    pub cantor_response: ProtocolResponse,
    pub candidate: CandidateArtifact,
    pub review: ReviewDecision,
    pub final_decision: FinalDecision,
    pub transcript: Vec<EcosystemMessageEnvelope>,
    pub metrics: CycleMetrics,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleFailure {
    pub profile: String,
    pub progress: CycleProgress,
    pub fault: EcosystemFault,
    pub accepted_prefix: Vec<EcosystemMessageEnvelope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcosystemFaultCode {
    UnsupportedProfile,
    InvalidIdentity,
    DuplicateIdentity,
    InvalidParticipant,
    InvalidText,
    InvalidDigest,
    InvalidBudget,
    InvalidLifetime,
    CommissionInactive,
    CommissionExpired,
    AuthorityDenied,
    MissingReviewCheck,
    MissingProof,
    MissingCriterion,
    WrongRecipient,
    FrameMismatch,
    CorrelationMismatch,
    BrokenCausation,
    PayloadKindMismatch,
    MessageReplay,
    IdempotencyReplay,
    SemanticCycle,
    BudgetExceeded,
    NonMonotonicTick,
    UnexpectedMessage,
    AdapterFault,
    ProtocolFault,
    ReviewRejected,
    OutcomeMismatch,
    SerializationFault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemFault {
    pub code: EcosystemFaultCode,
    pub stage: String,
    pub message: String,
    pub related_ids: Vec<SemanticId>,
}

impl EcosystemFault {
    pub fn new(
        code: EcosystemFaultCode,
        stage: impl Into<String>,
        message: impl AsRef<str>,
        related_ids: Vec<SemanticId>,
    ) -> Self {
        Self {
            code,
            stage: stage.into(),
            message: message
                .as_ref()
                .chars()
                .take(MAX_FAULT_MESSAGE_CHARS)
                .collect(),
            related_ids,
        }
    }

    pub fn validate(&self) -> Result<(), EcosystemFault> {
        validate_text("fault stage", &self.stage, "fault")?;
        validate_text("fault message", &self.message, "fault")?;
        validate_collection_len("fault related identities", self.related_ids.len(), "fault")
    }
}

impl fmt::Display for EcosystemFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} at {}: {}",
            self.code, self.stage, self.message
        )
    }
}

impl std::error::Error for EcosystemFault {}

pub(crate) fn validate_text(label: &str, value: &str, stage: &str) -> Result<(), EcosystemFault> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(EcosystemFault::new(
            EcosystemFaultCode::InvalidText,
            stage,
            format!("{label} must be nonempty, NUL-free, and at most {MAX_TEXT_BYTES} bytes"),
            Vec::new(),
        ));
    }
    Ok(())
}

fn validate_collection_len(label: &str, length: usize, stage: &str) -> Result<(), EcosystemFault> {
    if length > MAX_COLLECTION_ITEMS {
        return Err(EcosystemFault::new(
            EcosystemFaultCode::BudgetExceeded,
            stage,
            format!("{label} exceeds the {MAX_COLLECTION_ITEMS}-item profile limit"),
            Vec::new(),
        ));
    }
    Ok(())
}

const fn permitted_response(kind: MessageKind) -> Option<MessageKind> {
    match kind {
        MessageKind::Commission => Some(MessageKind::Assignment),
        MessageKind::Assignment => Some(MessageKind::CantorQuery),
        MessageKind::CantorQuery => Some(MessageKind::CantorReturn),
        MessageKind::CantorReturn => Some(MessageKind::Candidate),
        MessageKind::Candidate => Some(MessageKind::Review),
        MessageKind::Review => Some(MessageKind::Decision),
        MessageKind::Decision | MessageKind::Fault => None,
    }
}

pub(crate) fn validate_sha256(
    digest: &ContentDigest,
    stage: &str,
    related_ids: Vec<SemanticId>,
) -> Result<(), EcosystemFault> {
    let valid = digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(EcosystemFault::new(
            EcosystemFaultCode::InvalidDigest,
            stage,
            "digest must use lowercase hexadecimal SHA-256",
            related_ids,
        ))
    }
}

pub(crate) fn criteria_by_id(packet: &WorkPacket) -> BTreeMap<SemanticId, &AcceptanceCriterion> {
    packet
        .acceptance_criteria
        .iter()
        .map(|criterion| (criterion.criterion_id.clone(), criterion))
        .collect()
}
