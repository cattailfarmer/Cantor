use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ContentDigest, FacultyKind, SemanticId};

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    Observed,
    Inferred,
    Assumed,
    Imagined,
    Verified,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedFrameStatus {
    Working,
    CandidateFrozen,
    Sealed,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationDisposition {
    Applied,
    Buffered,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationDisposition {
    Acknowledge,
    Challenge,
    Defer,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDisposition {
    Sealed,
    RevisionRequired,
    Deferred,
    Incomplete,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DreamStatus {
    Open,
    Testing,
    Verified,
    Discarded,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DreamReviewDisposition {
    Verified,
    RevisionRequired,
    Deferred,
    Incomplete,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedAttentionFaultCode {
    InvalidFrame,
    InvalidLedger,
    InvalidDigest,
    InvalidTransition,
    UnknownParticipant,
    UnauthorizedFaculty,
    StaleBase,
    StaleLedger,
    DuplicateIdentity,
    ConflictingMutation,
    UnknownReference,
    UnknownSession,
    UnknownEvent,
    DigestCollision,
    EpistemicBoundary,
    CapacityOverflow,
    UnresolvedChallenge,
    MissingAttestation,
    DreamBoundary,
    MachineForm,
}

impl SharedAttentionFaultCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFrame => "invalid_frame",
            Self::InvalidLedger => "invalid_ledger",
            Self::InvalidDigest => "invalid_digest",
            Self::InvalidTransition => "invalid_transition",
            Self::UnknownParticipant => "unknown_participant",
            Self::UnauthorizedFaculty => "unauthorized_faculty",
            Self::StaleBase => "stale_base",
            Self::StaleLedger => "stale_ledger",
            Self::DuplicateIdentity => "duplicate_identity",
            Self::ConflictingMutation => "conflicting_mutation",
            Self::UnknownReference => "unknown_reference",
            Self::UnknownSession => "unknown_session",
            Self::UnknownEvent => "unknown_event",
            Self::DigestCollision => "digest_collision",
            Self::EpistemicBoundary => "epistemic_boundary",
            Self::CapacityOverflow => "capacity_overflow",
            Self::UnresolvedChallenge => "unresolved_challenge",
            Self::MissingAttestation => "missing_attestation",
            Self::DreamBoundary => "dream_boundary",
            Self::MachineForm => "machine_form",
        }
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAttentionFault {
    pub code: SharedAttentionFaultCode,
    pub message: String,
    pub subject_refs: BTreeSet<SemanticId>,
}

impl SharedAttentionFault {
    pub(crate) fn new(code: SharedAttentionFaultCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            subject_refs: BTreeSet::new(),
        }
    }

    pub(crate) fn with_subject(mut self, subject: SemanticId) -> Self {
        self.subject_refs.insert(subject);
        self
    }
}

impl fmt::Display for SharedAttentionFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for SharedAttentionFault {}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionParticipant {
    pub participant_id: SemanticId,
    pub faculties: BTreeSet<FacultyKind>,
    pub required: bool,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FramedProposition {
    pub proposition_id: SemanticId,
    pub text: String,
    pub epistemic_status: EpistemicStatus,
    pub source_refs: BTreeSet<SemanticId>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub dream_ref: Option<SemanticId>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionCapacity {
    pub accounting_profile: String,
    pub context_budget_bytes: u64,
    pub pinned_anchor_bytes: u64,
    pub current_focus_bytes: u64,
    pub retrieved_association_bytes: u64,
    pub recent_stream_bytes: u64,
    pub reserved_headroom_bytes: u64,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAttentionFrameSeed {
    pub frame_id: SemanticId,
    pub purpose: String,
    pub policy_ref: SemanticId,
    pub participants: BTreeMap<SemanticId, AttentionParticipant>,
    pub propositions: BTreeMap<SemanticId, FramedProposition>,
    pub constraints: BTreeMap<SemanticId, String>,
    pub pinned_sop_anchor_refs: BTreeSet<SemanticId>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub current_focus_refs: BTreeSet<SemanticId>,
    pub capacity: AttentionCapacity,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAttentionFrame {
    pub profile: String,
    pub frame_id: SemanticId,
    pub generation: u64,
    pub predecessor_frame_digest: Option<ContentDigest>,
    pub purpose: String,
    pub policy_ref: SemanticId,
    pub participants: BTreeMap<SemanticId, AttentionParticipant>,
    pub propositions: BTreeMap<SemanticId, FramedProposition>,
    pub constraints: BTreeMap<SemanticId, String>,
    pub pinned_sop_anchor_refs: BTreeSet<SemanticId>,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub challenges: BTreeMap<SemanticId, String>,
    pub current_focus_refs: BTreeSet<SemanticId>,
    pub capacity: AttentionCapacity,
    pub applied_delta_refs: BTreeSet<SemanticId>,
    pub applied_compaction_refs: BTreeSet<SemanticId>,
    pub settlement_attestation_refs: BTreeSet<SemanticId>,
    pub status: SharedFrameStatus,
    pub semantic_digest: ContentDigest,
    pub frame_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operator", rename_all = "snake_case", deny_unknown_fields)]
pub enum FrameDeltaOperation {
    AddProposition {
        proposition: FramedProposition,
    },
    ReplaceProposition {
        proposition: FramedProposition,
    },
    RemoveProposition {
        proposition_ref: SemanticId,
    },
    AddConstraint {
        constraint_id: SemanticId,
        text: String,
    },
    RemoveConstraint {
        constraint_ref: SemanticId,
    },
    PinAnchor {
        anchor_ref: SemanticId,
    },
    ReleaseAnchor {
        anchor_ref: SemanticId,
    },
    AttachEvidence {
        evidence_ref: SemanticId,
    },
    RaiseChallenge {
        challenge_id: SemanticId,
        text: String,
    },
    ResolveChallenge {
        challenge_ref: SemanticId,
    },
    SetFocus {
        proposition_ref: SemanticId,
    },
    ReleaseFocus {
        proposition_ref: SemanticId,
    },
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionFrameDelta {
    pub profile: String,
    pub delta_id: SemanticId,
    pub author_ref: SemanticId,
    pub policy_ref: SemanticId,
    pub base_generation: u64,
    pub base_frame_digest: ContentDigest,
    pub logical_time: u64,
    pub operations: Vec<FrameDeltaOperation>,
    pub causal_predecessor_refs: BTreeSet<SemanticId>,
    pub delta_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackpressureReceipt {
    pub receipt_id: SemanticId,
    pub base_frame_digest: ContentDigest,
    pub required_novelty_bytes: u64,
    pub available_headroom_bytes: u64,
    pub accounting_profile: String,
    pub buffered_delta_refs: BTreeSet<SemanticId>,
    pub recovery_actions: Vec<String>,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionCompaction {
    pub profile: String,
    pub compaction_id: SemanticId,
    pub actor_ref: SemanticId,
    pub policy_ref: SemanticId,
    pub base_generation: u64,
    pub base_frame_digest: ContentDigest,
    pub retained_focus_refs: BTreeSet<SemanticId>,
    pub current_focus_bytes_after: u64,
    pub retrieved_association_bytes_after: u64,
    pub recent_stream_bytes_after: u64,
    pub rationale: String,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub compaction_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionCompactionReceipt {
    pub receipt_id: SemanticId,
    pub compaction_ref: SemanticId,
    pub predecessor_frame_digest: ContentDigest,
    pub successor_frame_digest: ContentDigest,
    pub released_focus_refs: BTreeSet<SemanticId>,
    pub headroom_before_bytes: u64,
    pub headroom_after_bytes: u64,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionCompactionOutcome {
    pub successor: SharedAttentionFrame,
    pub receipt: AttentionCompactionReceipt,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameTransitionReceipt {
    pub transition_id: SemanticId,
    pub predecessor_frame_digest: ContentDigest,
    pub successor_frame_digest: ContentDigest,
    pub applied_delta_refs: BTreeSet<SemanticId>,
    pub novelty_bytes: u64,
    pub transition_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameReconciliation {
    pub disposition: ReconciliationDisposition,
    pub base_frame_digest: ContentDigest,
    pub successor: Option<SharedAttentionFrame>,
    pub transition_receipt: Option<FrameTransitionReceipt>,
    pub backpressure_receipt: Option<BackpressureReceipt>,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePreparationReceipt {
    pub receipt_id: SemanticId,
    pub working_frame_digest: ContentDigest,
    pub candidate_frame_digest: ContentDigest,
    pub candidate_generation: u64,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAttentionCandidate {
    pub candidate: SharedAttentionFrame,
    pub receipt: CandidatePreparationReceipt,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameAttestation {
    pub profile: String,
    pub attestation_id: SemanticId,
    pub participant_ref: SemanticId,
    pub faculty: FacultyKind,
    pub candidate_generation: u64,
    pub candidate_frame_digest: ContentDigest,
    pub disposition: AttestationDisposition,
    pub rationale: String,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub attestation_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementReceipt {
    pub receipt_id: SemanticId,
    pub candidate_frame_digest: ContentDigest,
    pub sealed_frame_digest: Option<ContentDigest>,
    pub disposition: SettlementDisposition,
    pub attestation_refs: BTreeSet<SemanticId>,
    pub missing_participant_refs: BTreeSet<SemanticId>,
    pub missing_gate_faculties: BTreeSet<FacultyKind>,
    pub challenge_refs: BTreeSet<SemanticId>,
    pub defer_refs: BTreeSet<SemanticId>,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementOutcome {
    pub disposition: SettlementDisposition,
    pub sealed_frame: Option<SharedAttentionFrame>,
    pub receipt: SettlementReceipt,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamFrameSeed {
    pub dream_id: SemanticId,
    pub parent_frame_digest: ContentDigest,
    pub purpose: String,
    pub preserved_invariant_refs: BTreeSet<SemanticId>,
    pub relaxed_assumptions: BTreeMap<SemanticId, String>,
    pub forbidden_effects: BTreeSet<String>,
    pub hypotheses: BTreeMap<SemanticId, FramedProposition>,
    pub predicted_consequences: BTreeMap<SemanticId, String>,
    pub required_evidence_refs: BTreeSet<SemanticId>,
    pub falsification_conditions: BTreeSet<String>,
    pub depth: u32,
    pub maximum_depth: u32,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamFrame {
    pub profile: String,
    pub dream_id: SemanticId,
    pub parent_frame_id: SemanticId,
    pub parent_generation: u64,
    pub parent_frame_digest: ContentDigest,
    pub purpose: String,
    pub preserved_invariant_refs: BTreeSet<SemanticId>,
    pub relaxed_assumptions: BTreeMap<SemanticId, String>,
    pub forbidden_effects: BTreeSet<String>,
    pub hypotheses: BTreeMap<SemanticId, FramedProposition>,
    pub predicted_consequences: BTreeMap<SemanticId, String>,
    pub required_evidence_refs: BTreeSet<SemanticId>,
    pub observed_evidence_refs: BTreeSet<SemanticId>,
    pub falsification_conditions: BTreeSet<String>,
    pub depth: u32,
    pub maximum_depth: u32,
    pub verification_review_refs: BTreeSet<SemanticId>,
    pub status: DreamStatus,
    pub dream_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamReview {
    pub profile: String,
    pub review_id: SemanticId,
    pub dream_ref: SemanticId,
    pub base_dream_digest: ContentDigest,
    pub reviewer_ref: SemanticId,
    pub faculty: FacultyKind,
    pub disposition: AttestationDisposition,
    pub rationale: String,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub review_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamReviewReceipt {
    pub receipt_id: SemanticId,
    pub predecessor_dream_digest: ContentDigest,
    pub successor_dream_digest: Option<ContentDigest>,
    pub disposition: DreamReviewDisposition,
    pub review_refs: BTreeSet<SemanticId>,
    pub missing_evidence_refs: BTreeSet<SemanticId>,
    pub missing_gate_faculties: BTreeSet<FacultyKind>,
    pub challenge_refs: BTreeSet<SemanticId>,
    pub defer_refs: BTreeSet<SemanticId>,
    pub receipt_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamReviewOutcome {
    pub disposition: DreamReviewDisposition,
    pub successor: Option<DreamFrame>,
    pub receipt: DreamReviewReceipt,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamDiscardReceipt {
    pub receipt_id: SemanticId,
    pub predecessor_dream_digest: ContentDigest,
    pub discarded_dream_digest: ContentDigest,
    pub reason: String,
    pub receipt_digest: ContentDigest,
}
