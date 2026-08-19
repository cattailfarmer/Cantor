//! Provider-neutral request, response, and dispatch seam for shared attention.
//!
//! This module is pure. CLI, MCP, or model-host adapters may carry these
//! forms, but semantic decisions remain the closed state transitions in this
//! crate.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    AttentionCompaction, AttentionCompactionOutcome, AttentionFrameDelta, DreamFrame,
    DreamFrameSeed, DreamReview, DreamReviewOutcome, EpistemicStatus, FrameAttestation,
    FrameReconciliation, PreparedAttentionCandidate, ReconciliationDisposition, SettlementOutcome,
    SharedAttentionFault, SharedAttentionFrame, compact_attention_frame, discard_dream_frame,
    fork_dream_frame, prepare_attention_candidate, project_dream_promotion,
    reconcile_attention_deltas, record_dream_evidence, review_dream_frame,
    settle_attention_candidate, validate_dream_frame, validate_shared_attention_frame,
};
use crate::SemanticId;

/// Retains the first JSON shell's profile so existing callers remain wire
/// compatible while sharing the same response with later adapters.
pub const SHARED_ATTENTION_TOOL_RESPONSE_PROFILE: &str = "cantor-shared-attention-cli/0.1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum SharedAttentionToolRequest {
    ValidateFrame {
        frame: SharedAttentionFrame,
    },
    Reconcile {
        base: SharedAttentionFrame,
        deltas: Vec<AttentionFrameDelta>,
    },
    Compact {
        base: SharedAttentionFrame,
        compaction: AttentionCompaction,
    },
    Prepare {
        working: SharedAttentionFrame,
    },
    Settle {
        candidate: SharedAttentionFrame,
        attestations: Vec<FrameAttestation>,
    },
    ForkDream {
        parent: SharedAttentionFrame,
        seed: DreamFrameSeed,
    },
    ValidateDream {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
    },
    RecordDreamEvidence {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        evidence_refs: BTreeSet<SemanticId>,
    },
    ReviewDream {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        reviews: Vec<DreamReview>,
    },
    DiscardDream {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        reason: String,
    },
    ProjectDreamPromotion {
        parent: SharedAttentionFrame,
        dream: DreamFrame,
        delta_id: SemanticId,
        author_ref: SemanticId,
        target_status: EpistemicStatus,
        logical_time: u64,
    },
}

impl SharedAttentionToolRequest {
    pub const fn operation_name(&self) -> &'static str {
        match self {
            Self::ValidateFrame { .. } => "validate_frame",
            Self::Reconcile { .. } => "reconcile",
            Self::Compact { .. } => "compact",
            Self::Prepare { .. } => "prepare",
            Self::Settle { .. } => "settle",
            Self::ForkDream { .. } => "fork_dream",
            Self::ValidateDream { .. } => "validate_dream",
            Self::RecordDreamEvidence { .. } => "record_dream_evidence",
            Self::ReviewDream { .. } => "review_dream",
            Self::DiscardDream { .. } => "discard_dream",
            Self::ProjectDreamPromotion { .. } => "project_dream_promotion",
        }
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedAttentionToolStatus {
    Succeeded,
    Buffered,
    Refused,
    InvalidRequest,
    InternalFault,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAttentionToolFault {
    pub code: String,
    pub message: String,
    pub subject_refs: BTreeSet<SemanticId>,
}

impl From<SharedAttentionFault> for SharedAttentionToolFault {
    fn from(fault: SharedAttentionFault) -> Self {
        Self {
            code: fault.code.as_str().to_owned(),
            message: fault.message,
            subject_refs: fault.subject_refs,
        }
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamDiscardOutcome {
    pub dream: DreamFrame,
    pub receipt: super::DreamDiscardReceipt,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SharedAttentionToolResult {
    Frame(SharedAttentionFrame),
    Reconciliation(FrameReconciliation),
    Compaction(AttentionCompactionOutcome),
    Preparation(PreparedAttentionCandidate),
    Settlement(SettlementOutcome),
    Dream(DreamFrame),
    DreamReview(DreamReviewOutcome),
    DreamDiscard(DreamDiscardOutcome),
    PromotionDelta(AttentionFrameDelta),
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedAttentionToolResponse {
    pub profile: String,
    pub operation: String,
    pub status: SharedAttentionToolStatus,
    pub result: Option<SharedAttentionToolResult>,
    pub fault: Option<SharedAttentionToolFault>,
    pub nonclaims: Vec<String>,
}

impl SharedAttentionToolResponse {
    fn success(operation: &str, result: SharedAttentionToolResult) -> Self {
        Self::new(
            operation,
            SharedAttentionToolStatus::Succeeded,
            Some(result),
            None,
        )
    }

    fn buffered(operation: &str, result: SharedAttentionToolResult) -> Self {
        Self::new(
            operation,
            SharedAttentionToolStatus::Buffered,
            Some(result),
            None,
        )
    }

    fn domain_fault(operation: &str, fault: SharedAttentionFault) -> Self {
        Self::new(
            operation,
            SharedAttentionToolStatus::Refused,
            None,
            Some(fault.into()),
        )
    }

    pub fn invalid_request(code: &str, message: impl Into<String>) -> Self {
        Self::transport_fault(SharedAttentionToolStatus::InvalidRequest, code, message)
    }

    pub fn internal_fault(code: &str, message: impl Into<String>) -> Self {
        Self::transport_fault(SharedAttentionToolStatus::InternalFault, code, message)
    }

    fn transport_fault(
        status: SharedAttentionToolStatus,
        code: &str,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            "unavailable",
            status,
            None,
            Some(SharedAttentionToolFault {
                code: code.to_owned(),
                message: message.into(),
                subject_refs: BTreeSet::new(),
            }),
        )
    }

    fn new(
        operation: &str,
        status: SharedAttentionToolStatus,
        result: Option<SharedAttentionToolResult>,
        fault: Option<SharedAttentionToolFault>,
    ) -> Self {
        Self {
            profile: SHARED_ATTENTION_TOOL_RESPONSE_PROFILE.to_owned(),
            operation: operation.to_owned(),
            status,
            result,
            fault,
            nonclaims: vec![
                "no model hidden state or KV cache was shared".to_owned(),
                "no external effect was authorized or executed".to_owned(),
                "settlement is coordination and not proof of external truth".to_owned(),
            ],
        }
    }

    pub const fn exit_code(&self) -> u8 {
        match self.status {
            SharedAttentionToolStatus::Succeeded | SharedAttentionToolStatus::Buffered => 0,
            SharedAttentionToolStatus::InvalidRequest => 2,
            SharedAttentionToolStatus::Refused => 3,
            SharedAttentionToolStatus::InternalFault => 4,
        }
    }

    pub const fn is_error(&self) -> bool {
        !matches!(
            self.status,
            SharedAttentionToolStatus::Succeeded | SharedAttentionToolStatus::Buffered
        )
    }
}

pub fn execute_shared_attention_tool_request(
    request: SharedAttentionToolRequest,
) -> SharedAttentionToolResponse {
    let operation = request.operation_name();
    let result = match request {
        SharedAttentionToolRequest::ValidateFrame { frame } => {
            validate_shared_attention_frame(&frame)
                .map(|()| SharedAttentionToolResult::Frame(frame))
        }
        SharedAttentionToolRequest::Reconcile { base, deltas } => {
            return match reconcile_attention_deltas(&base, &deltas) {
                Ok(outcome) => {
                    let buffered = outcome.disposition == ReconciliationDisposition::Buffered;
                    let result = SharedAttentionToolResult::Reconciliation(outcome);
                    if buffered {
                        SharedAttentionToolResponse::buffered(operation, result)
                    } else {
                        SharedAttentionToolResponse::success(operation, result)
                    }
                }
                Err(fault) => SharedAttentionToolResponse::domain_fault(operation, fault),
            };
        }
        SharedAttentionToolRequest::Compact { base, compaction } => {
            compact_attention_frame(&base, &compaction).map(SharedAttentionToolResult::Compaction)
        }
        SharedAttentionToolRequest::Prepare { working } => {
            prepare_attention_candidate(&working).map(SharedAttentionToolResult::Preparation)
        }
        SharedAttentionToolRequest::Settle {
            candidate,
            attestations,
        } => settle_attention_candidate(&candidate, &attestations)
            .map(SharedAttentionToolResult::Settlement),
        SharedAttentionToolRequest::ForkDream { parent, seed } => {
            fork_dream_frame(&parent, seed).map(SharedAttentionToolResult::Dream)
        }
        SharedAttentionToolRequest::ValidateDream { parent, dream } => {
            validate_dream_frame(&parent, &dream).map(|()| SharedAttentionToolResult::Dream(dream))
        }
        SharedAttentionToolRequest::RecordDreamEvidence {
            parent,
            dream,
            evidence_refs,
        } => record_dream_evidence(&parent, &dream, &evidence_refs)
            .map(SharedAttentionToolResult::Dream),
        SharedAttentionToolRequest::ReviewDream {
            parent,
            dream,
            reviews,
        } => review_dream_frame(&parent, &dream, &reviews)
            .map(SharedAttentionToolResult::DreamReview),
        SharedAttentionToolRequest::DiscardDream {
            parent,
            dream,
            reason,
        } => discard_dream_frame(&parent, &dream, reason).map(|(dream, receipt)| {
            SharedAttentionToolResult::DreamDiscard(DreamDiscardOutcome { dream, receipt })
        }),
        SharedAttentionToolRequest::ProjectDreamPromotion {
            parent,
            dream,
            delta_id,
            author_ref,
            target_status,
            logical_time,
        } => project_dream_promotion(
            &parent,
            &dream,
            delta_id,
            author_ref,
            target_status,
            logical_time,
        )
        .map(SharedAttentionToolResult::PromotionDelta),
    };
    match result {
        Ok(result) => SharedAttentionToolResponse::success(operation, result),
        Err(fault) => SharedAttentionToolResponse::domain_fault(operation, fault),
    }
}
