//! Provider-neutral forms and pure dispatch for resumable coordination.
//!
//! Every request carries its complete admitted context. This module stores no
//! state, reimplements no checkpoint validation, and performs no I/O.

use cantor_core::{
    AdmissionDisposition, AuthorshipLaneEvidence, CantorProcessIr, CompiledProcedureIdentity,
    CoordinationCheckpoint, CoordinationSliceTransition, EvaluationFault, FaultKind,
    InvocationRequest, NegotiationSession, ProcedureCatalogueState,
    advance_coordination_checkpoint, begin_coordination_checkpoint,
};
use serde::{Deserialize, Serialize};

pub const COORDINATION_TOOL_PROFILE: &str = "cantor-resumable-coordination-tool/0.1";
pub const COORDINATION_TOOL_MAX_FAULT_CHARS: usize = 1024;

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationToolContext {
    pub catalogue: Box<ProcedureCatalogueState>,
    pub procedure: Box<CompiledProcedureIdentity>,
    pub ir: Box<CantorProcessIr>,
    pub admission: Box<AdmissionDisposition>,
    pub request: Box<InvocationRequest>,
    pub initial_session: Box<NegotiationSession>,
}

impl From<&AuthorshipLaneEvidence> for CoordinationToolContext {
    fn from(lane: &AuthorshipLaneEvidence) -> Self {
        Self {
            catalogue: Box::new(lane.catalogue.clone()),
            procedure: Box::new(lane.procedure.clone()),
            ir: Box::new(lane.ir.clone()),
            admission: Box::new(lane.admission.clone()),
            request: Box::new(lane.request.clone()),
            initial_session: Box::new(lane.initial_session.clone()),
        }
    }
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinationToolRequest {
    Begin {
        context: Box<CoordinationToolContext>,
    },
    Advance {
        context: Box<CoordinationToolContext>,
        checkpoint: Box<CoordinationCheckpoint>,
        maximum_steps: u64,
    },
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationToolOperation {
    Begin,
    Advance,
    Unavailable,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationToolStatus {
    Succeeded,
    Refused,
    InvalidRequest,
    InternalFault,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinationToolResult {
    Began {
        checkpoint: Box<CoordinationCheckpoint>,
    },
    Advanced {
        transition: Box<CoordinationSliceTransition>,
    },
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationToolFault {
    pub code: String,
    pub category: String,
    pub message: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationToolResponse {
    pub profile: String,
    pub operation: CoordinationToolOperation,
    pub status: CoordinationToolStatus,
    pub result: Option<CoordinationToolResult>,
    pub fault: Option<CoordinationToolFault>,
    pub nonclaims: Vec<String>,
}

impl CoordinationToolResponse {
    #[must_use]
    pub fn invalid(
        operation: CoordinationToolOperation,
        code: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::failed(
            operation,
            CoordinationToolStatus::InvalidRequest,
            code,
            "invalid_request",
            message,
        )
    }

    #[must_use]
    pub fn internal(
        operation: CoordinationToolOperation,
        code: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self::failed(
            operation,
            CoordinationToolStatus::InternalFault,
            code,
            "internal_fault",
            message,
        )
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        !matches!(self.status, CoordinationToolStatus::Succeeded)
    }

    fn succeeded(operation: CoordinationToolOperation, result: CoordinationToolResult) -> Self {
        Self {
            profile: COORDINATION_TOOL_PROFILE.to_owned(),
            operation,
            status: CoordinationToolStatus::Succeeded,
            result: Some(result),
            fault: None,
            nonclaims: nonclaims(),
        }
    }

    fn refused(operation: CoordinationToolOperation, fault: EvaluationFault) -> Self {
        Self::failed(
            operation,
            CoordinationToolStatus::Refused,
            "coordination_refused",
            fault_kind_name(&fault.kind),
            fault.message,
        )
    }

    fn failed(
        operation: CoordinationToolOperation,
        status: CoordinationToolStatus,
        code: impl Into<String>,
        category: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        Self {
            profile: COORDINATION_TOOL_PROFILE.to_owned(),
            operation,
            status,
            result: None,
            fault: Some(CoordinationToolFault {
                code: code.into(),
                category: category.into(),
                message: bounded(message.as_ref()),
            }),
            nonclaims: nonclaims(),
        }
    }
}

#[must_use]
pub fn execute_coordination_tool_request(
    request: CoordinationToolRequest,
) -> CoordinationToolResponse {
    match request {
        CoordinationToolRequest::Begin { context } => {
            let operation = CoordinationToolOperation::Begin;
            match begin_coordination_checkpoint(
                &context.catalogue,
                &context.procedure,
                &context.ir,
                &context.admission,
                &context.request,
                &context.initial_session,
            ) {
                Ok(checkpoint) => CoordinationToolResponse::succeeded(
                    operation,
                    CoordinationToolResult::Began {
                        checkpoint: Box::new(checkpoint),
                    },
                ),
                Err(fault) => CoordinationToolResponse::refused(operation, fault),
            }
        }
        CoordinationToolRequest::Advance {
            context,
            checkpoint,
            maximum_steps,
        } => {
            let operation = CoordinationToolOperation::Advance;
            if maximum_steps == 0 {
                return CoordinationToolResponse::invalid(
                    operation,
                    "zero_step_quota",
                    "maximum_steps must be greater than zero",
                );
            }
            match advance_coordination_checkpoint(
                &context.catalogue,
                &context.procedure,
                &context.ir,
                &context.admission,
                &context.request,
                &context.initial_session,
                &checkpoint,
                maximum_steps,
            ) {
                Ok(transition) => CoordinationToolResponse::succeeded(
                    operation,
                    CoordinationToolResult::Advanced {
                        transition: Box::new(transition),
                    },
                ),
                Err(fault) => CoordinationToolResponse::refused(operation, fault),
            }
        }
    }
}

fn fault_kind_name(kind: &FaultKind) -> &'static str {
    match kind {
        FaultKind::InvalidIdentity => "invalid_identity",
        FaultKind::BudgetExhausted => "budget_exhausted",
        FaultKind::UnknownKnowledge => "unknown_knowledge",
        FaultKind::ConstraintViolation => "constraint_violation",
        FaultKind::UnauthorizedEffect => "unauthorized_effect",
        FaultKind::InvalidReentry => "invalid_reentry",
        FaultKind::SemanticLoss => "semantic_loss",
        FaultKind::MachineForm => "machine_form",
        FaultKind::UnsupportedSurface => "unsupported_surface",
        FaultKind::ReviewFailure => "review_failure",
    }
}

fn bounded(message: &str) -> String {
    message
        .chars()
        .take(COORDINATION_TOOL_MAX_FAULT_CHARS)
        .collect()
}

fn nonclaims() -> Vec<String> {
    vec![
        "the adapter stores no coordination state".to_owned(),
        "no model provider hidden state or live forward pass was accessed".to_owned(),
        "checkpoint integrity does not authenticate its producer or prove semantic truth"
            .to_owned(),
        "no external effect or host tool registration was performed".to_owned(),
    ]
}
