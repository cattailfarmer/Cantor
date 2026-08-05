//! Pure transport forms and dispatch for the effectless Cantor procedure tool.
//!
//! This crate has no argument, filesystem, standard-stream, provider, service,
//! network, model, persistence, or hardware behavior. Process adapters decode a
//! closed request, invoke one of these functions, and project the returned form.

use std::collections::BTreeMap;

use cantor_core::{
    AuthorshipLaneEvidence, AuthorshipLaneTemplate, ContentDigest, ExchangeOperation,
    FakeControllerOutcome, ProcedureCandidate, ProviderNeutralToolSchema, SemanticId,
    SopAnchorBinding, ToolCallProposal, ToolResultDisposition, compute_tool_call_argument_digest,
    provider_neutral_exchange_schema, run_authorship_lane, run_fake_controller_exchange,
    verify_fake_controller_outcome,
};
use serde::{Deserialize, Serialize};

pub const RESPONSE_PROFILE: &str = "cantor-procedure-tool-cli/0.1";
pub const PREPARATION_PROFILE: &str = "cantor-procedure-tool-preparation/0.1";
pub const RELEASE_GRADE: &str = "effectless_internal_experiment_only";
pub const MAX_MESSAGE_CHARS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureToolResponseStatus {
    Success,
    Refused,
    InvalidInput,
    VerificationFailure,
    InternalFault,
}

impl ProcedureToolResponseStatus {
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::InvalidInput => 2,
            Self::Refused => 3,
            Self::VerificationFailure => 4,
            Self::InternalFault => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureToolFault {
    pub code: String,
    pub stage: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureToolVerification {
    pub schema_digest: ContentDigest,
    pub call_ref: SemanticId,
    pub result_digest: ContentDigest,
    pub transcript_digest: ContentDigest,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcedureToolResponse {
    pub profile: String,
    pub grade: String,
    pub operation: String,
    pub status: ProcedureToolResponseStatus,
    pub schema: Option<ProviderNeutralToolSchema>,
    pub outcome: Option<FakeControllerOutcome>,
    pub verification: Option<ProcedureToolVerification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepared_request: Option<PreparedRunRequest>,
    pub faults: Vec<ProcedureToolFault>,
    pub residuals: Vec<String>,
}

impl ProcedureToolResponse {
    #[must_use]
    pub fn empty(operation: impl Into<String>, status: ProcedureToolResponseStatus) -> Self {
        Self {
            profile: RESPONSE_PROFILE.to_owned(),
            grade: RELEASE_GRADE.to_owned(),
            operation: operation.into(),
            status,
            schema: None,
            outcome: None,
            verification: None,
            prepared_request: None,
            faults: Vec::new(),
            residuals: vec![
                "no model or provider was called".to_owned(),
                "no external semantic effect was performed".to_owned(),
                "this result is not production qualification".to_owned(),
            ],
        }
    }

    #[must_use]
    pub fn fault(
        operation: impl Into<String>,
        status: ProcedureToolResponseStatus,
        code: impl Into<String>,
        stage: impl Into<String>,
        message: impl AsRef<str>,
    ) -> Self {
        let mut response = Self::empty(operation, status);
        response.faults.push(ProcedureToolFault {
            code: code.into(),
            stage: stage.into(),
            message: bounded(message.as_ref()),
        });
        response
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub candidate: ProcedureCandidate,
    pub template: AuthorshipLaneTemplate,
    pub recognized_anchors: BTreeMap<SemanticId, SopAnchorBinding>,
    pub call_id: SemanticId,
    pub inference_job_ref: SemanticId,
    pub pass_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRunRequest {
    pub schema: ProviderNeutralToolSchema,
    pub proposal: ToolCallProposal,
    pub lane: AuthorshipLaneEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub schema: ProviderNeutralToolSchema,
    pub proposal: ToolCallProposal,
    pub lane: AuthorshipLaneEvidence,
    pub outcome: FakeControllerOutcome,
}

#[must_use]
pub fn schema_response() -> ProcedureToolResponse {
    match provider_neutral_exchange_schema() {
        Ok(schema) => {
            let mut response =
                ProcedureToolResponse::empty("schema", ProcedureToolResponseStatus::Success);
            response.schema = Some(schema);
            response
        }
        Err(fault) => ProcedureToolResponse::fault(
            "schema",
            ProcedureToolResponseStatus::InternalFault,
            "schema_construction_failed",
            "schema",
            fault.to_string(),
        ),
    }
}

#[must_use]
pub fn prepare_response(request: PrepareRequest) -> ProcedureToolResponse {
    if request.pass_index == u64::MAX {
        return ProcedureToolResponse::fault(
            "prepare",
            ProcedureToolResponseStatus::InvalidInput,
            "pass_index_exhausted",
            "preparation",
            "pass_index must leave capacity for the later-pass successor",
        );
    }
    let lane = match run_authorship_lane(
        &request.candidate,
        &request.template,
        &request.recognized_anchors,
    ) {
        Ok(lane) => lane,
        Err(fault) => {
            return ProcedureToolResponse::fault(
                "prepare",
                ProcedureToolResponseStatus::Refused,
                "lane_preparation_refused",
                "preparation",
                fault.to_string(),
            );
        }
    };
    let schema = match provider_neutral_exchange_schema() {
        Ok(schema) => schema,
        Err(fault) => {
            return ProcedureToolResponse::fault(
                "prepare",
                ProcedureToolResponseStatus::InternalFault,
                "schema_construction_failed",
                "preparation",
                fault.to_string(),
            );
        }
    };
    let mut proposal = ToolCallProposal {
        schema_ref: schema.schema_id.clone(),
        schema_digest: schema.schema_digest.clone(),
        call_id: request.call_id,
        inference_job_ref: request.inference_job_ref,
        participant_ref: lane.request.caller_ref.clone(),
        pass_index: request.pass_index,
        operation: ExchangeOperation::Reconcile,
        invocation: lane.request.clone(),
        session: lane.initial_session.clone(),
        argument_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    };
    proposal.argument_digest = match compute_tool_call_argument_digest(&proposal) {
        Ok(digest) => digest,
        Err(fault) => {
            return ProcedureToolResponse::fault(
                "prepare",
                ProcedureToolResponseStatus::InternalFault,
                "proposal_digest_failed",
                "preparation",
                fault.to_string(),
            );
        }
    };
    let mut response =
        ProcedureToolResponse::empty("prepare", ProcedureToolResponseStatus::Success);
    response.profile = PREPARATION_PROFILE.to_owned();
    response.prepared_request = Some(PreparedRunRequest {
        schema,
        proposal,
        lane,
    });
    response
}

#[must_use]
pub fn run_response(request: PreparedRunRequest) -> ProcedureToolResponse {
    let outcome =
        match run_fake_controller_exchange(&request.schema, &request.proposal, &request.lane) {
            Ok(outcome) => outcome,
            Err(fault) => {
                return ProcedureToolResponse::fault(
                    "run",
                    ProcedureToolResponseStatus::InternalFault,
                    "controller_execution_failed",
                    "controller",
                    fault.to_string(),
                );
            }
        };
    if let Err(fault) =
        verify_fake_controller_outcome(&request.schema, &request.proposal, &request.lane, &outcome)
    {
        return ProcedureToolResponse::fault(
            "run",
            ProcedureToolResponseStatus::VerificationFailure,
            "generated_outcome_verification_failed",
            "verification",
            fault.to_string(),
        );
    }
    let status = match outcome.result.disposition {
        ToolResultDisposition::Completed => ProcedureToolResponseStatus::Success,
        ToolResultDisposition::Refused => ProcedureToolResponseStatus::Refused,
    };
    let mut response = ProcedureToolResponse::empty("run", status);
    if status == ProcedureToolResponseStatus::Refused {
        response.faults = outcome
            .result
            .faults
            .iter()
            .map(|fault| ProcedureToolFault {
                code: fault.code.clone(),
                stage: fault.stage.clone(),
                message: bounded(&fault.message),
            })
            .collect();
    }
    response.outcome = Some(outcome);
    response
}

#[must_use]
pub fn verify_response(request: VerifyRequest) -> ProcedureToolResponse {
    if let Err(fault) = verify_fake_controller_outcome(
        &request.schema,
        &request.proposal,
        &request.lane,
        &request.outcome,
    ) {
        return ProcedureToolResponse::fault(
            "verify",
            ProcedureToolResponseStatus::VerificationFailure,
            "outcome_verification_failed",
            "verification",
            fault.to_string(),
        );
    }
    let mut response = ProcedureToolResponse::empty("verify", ProcedureToolResponseStatus::Success);
    response.verification = Some(ProcedureToolVerification {
        schema_digest: request.schema.schema_digest,
        call_ref: request.proposal.call_id,
        result_digest: request.outcome.result.result_digest,
        transcript_digest: request.outcome.transcript.transcript_digest,
        verified: true,
    });
    response
}

fn bounded(message: &str) -> String {
    message.chars().take(MAX_MESSAGE_CHARS).collect()
}
