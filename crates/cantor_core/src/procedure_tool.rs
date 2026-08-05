//! Provider-neutral, effectless tool boundary for CPPE-I08.
//!
//! This module models a controller checkpoint as immutable data. It does not
//! call a provider, continue a decode pass, inspect hidden state, or perform an
//! external effect. A later inference pass can only receive the explicit
//! [`LaterPassContext`] emitted here.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::procedure_authorship::validate_lane_evidence;
use crate::procedure_runtime::{derived_id, digest_serialized, empty_sha256, machine_fault};
use crate::{
    AuthorshipLaneEvidence, ContentDigest, CoordinationOutcome, EvaluationFault,
    InvocationDisposition, InvocationRequest, NegotiationSession, ProcedureValue, SemanticId,
    SensitivityClass, coordinate_catalogued_procedure,
};

pub const CANTOR_EXCHANGE_SCHEMA_VERSION: &str = "cantor.exchange/0.1";
pub const CPPE_FAKE_TOOL_CONTROLLER_ID: &str = "cantor-fake-tool-controller/0.1";

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeOperation {
    Propose,
    Challenge,
    Qualify,
    Cite,
    Reconcile,
    Poll,
    Acknowledge,
    Yield,
    Stop,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNeutralToolSchema {
    pub schema_id: SemanticId,
    pub tool_name: String,
    pub schema_version: String,
    pub operations: BTreeSet<ExchangeOperation>,
    pub executable_operations: BTreeSet<ExchangeOperation>,
    pub required_input_fields: BTreeSet<String>,
    pub required_output_fields: BTreeSet<String>,
    pub input_closed: bool,
    pub output_closed: bool,
    pub effect_class: String,
    pub checkpoint_contract: String,
    pub schema_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallProposal {
    pub schema_ref: SemanticId,
    pub schema_digest: ContentDigest,
    pub call_id: SemanticId,
    pub inference_job_ref: SemanticId,
    pub participant_ref: SemanticId,
    pub pass_index: u64,
    pub operation: ExchangeOperation,
    pub invocation: InvocationRequest,
    pub session: NegotiationSession,
    pub argument_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerEventKind {
    GenerationOpened,
    ToolCallProposed,
    GenerationStopped,
    ToolCallValidated,
    CantorInvoked,
    ToolResultReturned,
    ContextBound,
    LaterPassResumed,
    CallRefused,
    Completed,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerTranscriptEvent {
    pub event_id: SemanticId,
    pub index: u64,
    pub kind: ControllerEventKind,
    pub call_ref: SemanticId,
    pub logical_time: u64,
    pub payload_digest: ContentDigest,
    pub predecessor_ref: Option<SemanticId>,
    pub event_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolControllerFault {
    pub code: String,
    pub stage: String,
    pub message: String,
    pub related_refs: BTreeSet<SemanticId>,
    pub safe_residual: String,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultDisposition {
    Completed,
    Refused,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaterPassContext {
    pub inference_job_ref: SemanticId,
    pub source_call_ref: SemanticId,
    pub pass_index: u64,
    pub tool_result_digest: ContentDigest,
    pub value: ProcedureValue,
    pub sensitivity: SensitivityClass,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNeutralToolResult {
    pub result_id: SemanticId,
    pub call_ref: SemanticId,
    pub operation: ExchangeOperation,
    pub disposition: ToolResultDisposition,
    pub invocation_result_digest: Option<ContentDigest>,
    pub explicit_context: Option<LaterPassContext>,
    pub proof_refs: BTreeSet<SemanticId>,
    pub faults: Vec<ToolControllerFault>,
    pub residuals: BTreeSet<String>,
    pub result_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeControllerTranscript {
    pub transcript_id: SemanticId,
    pub controller_ref: SemanticId,
    pub inference_job_ref: SemanticId,
    pub call_ref: SemanticId,
    pub schema_digest: ContentDigest,
    pub events: Vec<ControllerTranscriptEvent>,
    pub result_digest: ContentDigest,
    pub provider_call_count: u64,
    pub external_effect_count: u64,
    pub transcript_digest: ContentDigest,
}

#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeControllerOutcome {
    pub result: ProviderNeutralToolResult,
    pub coordination: Option<CoordinationOutcome>,
    pub transcript: FakeControllerTranscript,
}

pub fn provider_neutral_exchange_schema() -> Result<ProviderNeutralToolSchema, EvaluationFault> {
    let mut schema = ProviderNeutralToolSchema {
        schema_id: SemanticId::new(CANTOR_EXCHANGE_SCHEMA_VERSION)?,
        tool_name: "cantor.exchange".to_owned(),
        schema_version: CANTOR_EXCHANGE_SCHEMA_VERSION.to_owned(),
        operations: BTreeSet::from([
            ExchangeOperation::Propose,
            ExchangeOperation::Challenge,
            ExchangeOperation::Qualify,
            ExchangeOperation::Cite,
            ExchangeOperation::Reconcile,
            ExchangeOperation::Poll,
            ExchangeOperation::Acknowledge,
            ExchangeOperation::Yield,
            ExchangeOperation::Stop,
        ]),
        executable_operations: BTreeSet::from([ExchangeOperation::Reconcile]),
        required_input_fields: BTreeSet::from([
            "schema_ref".to_owned(),
            "schema_digest".to_owned(),
            "call_id".to_owned(),
            "inference_job_ref".to_owned(),
            "participant_ref".to_owned(),
            "pass_index".to_owned(),
            "operation".to_owned(),
            "invocation".to_owned(),
            "session".to_owned(),
            "argument_digest".to_owned(),
        ]),
        required_output_fields: BTreeSet::from([
            "result_id".to_owned(),
            "call_ref".to_owned(),
            "operation".to_owned(),
            "disposition".to_owned(),
            "invocation_result_digest".to_owned(),
            "explicit_context".to_owned(),
            "proof_refs".to_owned(),
            "faults".to_owned(),
            "residuals".to_owned(),
            "result_digest".to_owned(),
        ]),
        input_closed: true,
        output_closed: true,
        effect_class: "effectless_external_checkpoint".to_owned(),
        checkpoint_contract:
            "stop_generation_then_validate_then_invoke_then_bind_result_then_start_later_pass"
                .to_owned(),
        schema_digest: empty_sha256(),
    };
    schema.schema_digest = compute_provider_neutral_tool_schema_digest(&schema)?;
    Ok(schema)
}

pub fn compute_provider_neutral_tool_schema_digest(
    schema: &ProviderNeutralToolSchema,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = schema.clone();
    body.schema_digest = empty_sha256();
    digest_serialized(&body, "provider-neutral tool schema")
}

pub fn compute_tool_call_argument_digest(
    proposal: &ToolCallProposal,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = proposal.clone();
    body.argument_digest = empty_sha256();
    digest_serialized(&body, "provider-neutral tool call arguments")
}

pub fn compute_tool_result_digest(
    result: &ProviderNeutralToolResult,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = result.clone();
    body.result_digest = empty_sha256();
    if let Some(context) = &mut body.explicit_context {
        context.tool_result_digest = empty_sha256();
    }
    digest_serialized(&body, "provider-neutral tool result")
}

pub fn compute_controller_transcript_digest(
    transcript: &FakeControllerTranscript,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = transcript.clone();
    body.transcript_digest = empty_sha256();
    digest_serialized(&body, "fake controller transcript")
}

pub fn run_fake_controller_exchange(
    schema: &ProviderNeutralToolSchema,
    proposal: &ToolCallProposal,
    lane: &AuthorshipLaneEvidence,
) -> Result<FakeControllerOutcome, EvaluationFault> {
    let mut events = Vec::new();
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::GenerationOpened,
        digest_serialized(
            &(&proposal.inference_job_ref, proposal.pass_index),
            "opened inference pass",
        )?,
    )?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::ToolCallProposed,
        compute_tool_call_argument_digest(proposal)?,
    )?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::GenerationStopped,
        digest_serialized(&proposal.call_id, "generation stop boundary")?,
    )?;

    if let Err(fault) = validate_tool_call(schema, proposal, lane) {
        return refused_outcome(schema, proposal, events, fault);
    }

    append_event(
        &mut events,
        proposal,
        ControllerEventKind::ToolCallValidated,
        digest_serialized(
            &(&proposal.schema_digest, &proposal.argument_digest),
            "validated tool call",
        )?,
    )?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::CantorInvoked,
        digest_serialized(&proposal.invocation.invocation_id, "Cantor invocation")?,
    )?;

    let coordination = coordinate_catalogued_procedure(
        &lane.catalogue,
        &lane.procedure,
        &lane.ir,
        &lane.admission,
        &proposal.invocation,
        &proposal.session,
    )?;
    if coordination.result.disposition != InvocationDisposition::Returned {
        return refused_outcome(
            schema,
            proposal,
            events,
            ToolControllerFault {
                code: "cantor_invocation_refused".to_owned(),
                stage: "cantor_invocation".to_owned(),
                message: "Cantor returned a non-returning invocation disposition".to_owned(),
                related_refs: BTreeSet::from([
                    proposal.call_id.clone(),
                    proposal.invocation.invocation_id.clone(),
                ]),
                safe_residual: "no later inference pass was resumed".to_owned(),
            },
        );
    }

    let invocation_result_digest =
        digest_serialized(&coordination.result, "controller invocation result")?;
    let context_value = explicit_result_value(&coordination, &invocation_result_digest);
    let context_seed = digest_serialized(
        &(
            &proposal.inference_job_ref,
            &proposal.call_id,
            proposal.pass_index.saturating_add(1),
            &context_value,
        ),
        "later pass context",
    )?;
    let mut result = ProviderNeutralToolResult {
        result_id: derived_id("cppe:tool-result", &context_seed)?,
        call_ref: proposal.call_id.clone(),
        operation: proposal.operation,
        disposition: ToolResultDisposition::Completed,
        invocation_result_digest: Some(invocation_result_digest),
        explicit_context: Some(LaterPassContext {
            inference_job_ref: proposal.inference_job_ref.clone(),
            source_call_ref: proposal.call_id.clone(),
            pass_index: proposal
                .pass_index
                .checked_add(1)
                .ok_or_else(|| machine_fault("later pass index overflow"))?,
            tool_result_digest: empty_sha256(),
            value: context_value,
            sensitivity: coordination.result.output_sensitivity,
        }),
        proof_refs: BTreeSet::from([
            lane.admission.disposition_id.clone(),
            lane.replay.receipt_id.clone(),
            coordination.result.semantic_trace.trace_id.clone(),
        ]),
        faults: Vec::new(),
        residuals: BTreeSet::from([
            "context is explicit input to a later pass, not hidden-state sharing".to_owned(),
            "no model or provider was called".to_owned(),
        ]),
        result_digest: empty_sha256(),
    };
    result.result_digest = compute_tool_result_digest(&result)?;
    if let Some(context) = &mut result.explicit_context {
        context.tool_result_digest = result.result_digest.clone();
    }

    append_event(
        &mut events,
        proposal,
        ControllerEventKind::ToolResultReturned,
        result.result_digest.clone(),
    )?;
    let context = result
        .explicit_context
        .as_ref()
        .ok_or_else(|| machine_fault("completed tool result omitted later-pass context"))?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::ContextBound,
        digest_serialized(context, "bound later-pass context")?,
    )?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::LaterPassResumed,
        digest_serialized(
            &(&context.inference_job_ref, context.pass_index),
            "later pass resume",
        )?,
    )?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::Completed,
        result.result_digest.clone(),
    )?;
    finish_outcome(schema, proposal, result, Some(coordination), events)
}

pub fn verify_fake_controller_outcome(
    schema: &ProviderNeutralToolSchema,
    proposal: &ToolCallProposal,
    lane: &AuthorshipLaneEvidence,
    outcome: &FakeControllerOutcome,
) -> Result<(), EvaluationFault> {
    validate_schema(schema).map_err(|fault| machine_fault(fault.message))?;
    if outcome.transcript.schema_digest != schema.schema_digest
        || outcome.transcript.inference_job_ref != proposal.inference_job_ref
        || outcome.transcript.call_ref != proposal.call_id
        || outcome.transcript.controller_ref.as_str() != CPPE_FAKE_TOOL_CONTROLLER_ID
        || outcome.transcript.provider_call_count != 0
        || outcome.transcript.external_effect_count != 0
        || outcome.transcript.result_digest != outcome.result.result_digest
        || compute_controller_transcript_digest(&outcome.transcript)?
            != outcome.transcript.transcript_digest
    {
        return Err(machine_fault(
            "fake controller transcript envelope mismatch",
        ));
    }
    verify_event_chain(proposal, &outcome.transcript.events)?;
    let kinds = outcome
        .transcript
        .events
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    let expected = match outcome.result.disposition {
        ToolResultDisposition::Completed => vec![
            ControllerEventKind::GenerationOpened,
            ControllerEventKind::ToolCallProposed,
            ControllerEventKind::GenerationStopped,
            ControllerEventKind::ToolCallValidated,
            ControllerEventKind::CantorInvoked,
            ControllerEventKind::ToolResultReturned,
            ControllerEventKind::ContextBound,
            ControllerEventKind::LaterPassResumed,
            ControllerEventKind::Completed,
        ],
        ToolResultDisposition::Refused => vec![
            ControllerEventKind::GenerationOpened,
            ControllerEventKind::ToolCallProposed,
            ControllerEventKind::GenerationStopped,
            ControllerEventKind::CallRefused,
            ControllerEventKind::Completed,
        ],
    };
    if kinds != expected {
        return Err(machine_fault(
            "controller stage order does not preserve stop, call, result, context, and resume boundaries",
        ));
    }
    match outcome.result.disposition {
        ToolResultDisposition::Completed => {
            let coordination = outcome.coordination.as_ref().ok_or_else(|| {
                machine_fault("completed tool outcome omitted Cantor coordination evidence")
            })?;
            let context = outcome.result.explicit_context.as_ref().ok_or_else(|| {
                machine_fault("completed tool outcome omitted explicit later-pass context")
            })?;
            if !outcome.result.faults.is_empty()
                || context.pass_index != proposal.pass_index.saturating_add(1)
                || context.source_call_ref != proposal.call_id
                || outcome.result.invocation_result_digest
                    != Some(digest_serialized(
                        &coordination.result,
                        "controller invocation result",
                    )?)
            {
                return Err(machine_fault("completed tool result evidence mismatch"));
            }
        }
        ToolResultDisposition::Refused => {
            if outcome.coordination.is_some()
                || outcome.result.faults.len() != 1
                || outcome.result.explicit_context.is_some()
            {
                return Err(machine_fault("refused tool result boundary mismatch"));
            }
        }
    }
    if outcome
        .result
        .explicit_context
        .as_ref()
        .is_some_and(|context| context.tool_result_digest != outcome.result.result_digest)
        || compute_tool_result_digest(&outcome.result)? != outcome.result.result_digest
    {
        return Err(machine_fault(
            "provider-neutral tool result digest mismatch",
        ));
    }
    let replay = run_fake_controller_exchange(schema, proposal, lane)?;
    if replay != *outcome {
        return Err(machine_fault(
            "fake controller outcome does not match exact authoritative replay",
        ));
    }
    Ok(())
}

fn validate_schema(schema: &ProviderNeutralToolSchema) -> Result<(), ToolControllerFault> {
    let expected = provider_neutral_exchange_schema().map_err(|fault| {
        controller_fault(
            "schema_construction_fault",
            "schema_validation",
            fault.message,
        )
    })?;
    if schema != &expected
        || compute_provider_neutral_tool_schema_digest(schema).ok()
            != Some(schema.schema_digest.clone())
    {
        return Err(controller_fault(
            "schema_mismatch",
            "schema_validation",
            "tool schema is stale, altered, incomplete, or not the exact provider-neutral profile",
        ));
    }
    Ok(())
}

fn validate_tool_call(
    schema: &ProviderNeutralToolSchema,
    proposal: &ToolCallProposal,
    lane: &AuthorshipLaneEvidence,
) -> Result<(), ToolControllerFault> {
    validate_schema(schema)?;
    if proposal.schema_ref != schema.schema_id || proposal.schema_digest != schema.schema_digest {
        return Err(controller_fault(
            "schema_reference_mismatch",
            "call_validation",
            "tool call does not pin the exact schema identity and digest",
        ));
    }
    if compute_tool_call_argument_digest(proposal).ok() != Some(proposal.argument_digest.clone()) {
        return Err(controller_fault(
            "argument_digest_mismatch",
            "call_validation",
            "tool call arguments changed after their digest was formed",
        ));
    }
    if !schema.operations.contains(&proposal.operation)
        || !schema.executable_operations.contains(&proposal.operation)
    {
        return Err(controller_fault(
            "operation_not_executable",
            "call_validation",
            "operation is named by the protocol but is not executable in this bounded profile",
        ));
    }
    if proposal.participant_ref != proposal.invocation.caller_ref {
        return Err(controller_fault(
            "participant_boundary_mismatch",
            "call_validation",
            "tool caller is not the exact declared invocation participant",
        ));
    }
    if proposal.invocation != lane.request || proposal.session != lane.initial_session {
        return Err(controller_fault(
            "invocation_lineage_mismatch",
            "call_validation",
            "tool call does not reproduce the admitted invocation and session lineage",
        ));
    }
    validate_lane_evidence(lane).map_err(|fault| {
        controller_fault("evidence_replay_failed", "call_validation", fault.message)
    })?;
    Ok(())
}

fn controller_fault(
    code: impl Into<String>,
    stage: impl Into<String>,
    message: impl Into<String>,
) -> ToolControllerFault {
    ToolControllerFault {
        code: code.into(),
        stage: stage.into(),
        message: message.into(),
        related_refs: BTreeSet::new(),
        safe_residual: "call refused before later-pass context was created".to_owned(),
    }
}

fn refused_outcome(
    schema: &ProviderNeutralToolSchema,
    proposal: &ToolCallProposal,
    mut events: Vec<ControllerTranscriptEvent>,
    mut fault: ToolControllerFault,
) -> Result<FakeControllerOutcome, EvaluationFault> {
    fault.related_refs.insert(proposal.call_id.clone());
    fault
        .related_refs
        .insert(proposal.inference_job_ref.clone());
    let fault_digest = digest_serialized(&fault, "tool controller fault")?;
    let mut result = ProviderNeutralToolResult {
        result_id: derived_id("cppe:tool-refusal", &fault_digest)?,
        call_ref: proposal.call_id.clone(),
        operation: proposal.operation,
        disposition: ToolResultDisposition::Refused,
        invocation_result_digest: None,
        explicit_context: None,
        proof_refs: BTreeSet::new(),
        faults: vec![fault],
        residuals: BTreeSet::from([
            "no Cantor invocation result was accepted".to_owned(),
            "no later inference pass was resumed".to_owned(),
            "no model or provider was called".to_owned(),
        ]),
        result_digest: empty_sha256(),
    };
    result.result_digest = compute_tool_result_digest(&result)?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::CallRefused,
        fault_digest,
    )?;
    append_event(
        &mut events,
        proposal,
        ControllerEventKind::Completed,
        result.result_digest.clone(),
    )?;
    finish_outcome(schema, proposal, result, None, events)
}

fn finish_outcome(
    schema: &ProviderNeutralToolSchema,
    proposal: &ToolCallProposal,
    result: ProviderNeutralToolResult,
    coordination: Option<CoordinationOutcome>,
    events: Vec<ControllerTranscriptEvent>,
) -> Result<FakeControllerOutcome, EvaluationFault> {
    let transcript_seed = digest_serialized(
        &(
            &proposal.inference_job_ref,
            &proposal.call_id,
            &schema.schema_digest,
            &events,
            &result.result_digest,
        ),
        "fake controller transcript identity",
    )?;
    let mut transcript = FakeControllerTranscript {
        transcript_id: derived_id("cppe:fake-controller-transcript", &transcript_seed)?,
        controller_ref: SemanticId::new(CPPE_FAKE_TOOL_CONTROLLER_ID)?,
        inference_job_ref: proposal.inference_job_ref.clone(),
        call_ref: proposal.call_id.clone(),
        schema_digest: schema.schema_digest.clone(),
        events,
        result_digest: result.result_digest.clone(),
        provider_call_count: 0,
        external_effect_count: 0,
        transcript_digest: empty_sha256(),
    };
    transcript.transcript_digest = compute_controller_transcript_digest(&transcript)?;
    Ok(FakeControllerOutcome {
        result,
        coordination,
        transcript,
    })
}

fn append_event(
    events: &mut Vec<ControllerTranscriptEvent>,
    proposal: &ToolCallProposal,
    kind: ControllerEventKind,
    payload_digest: ContentDigest,
) -> Result<(), EvaluationFault> {
    let index = events.len() as u64;
    let predecessor_ref = events.last().map(|event| event.event_id.clone());
    let seed = digest_serialized(
        &(
            &proposal.call_id,
            index,
            kind,
            &payload_digest,
            &predecessor_ref,
        ),
        "controller transcript event identity",
    )?;
    let mut event = ControllerTranscriptEvent {
        event_id: derived_id("cppe:controller-event", &seed)?,
        index,
        kind,
        call_ref: proposal.call_id.clone(),
        logical_time: proposal
            .invocation
            .initial_logical_time
            .checked_add(index)
            .ok_or_else(|| machine_fault("controller logical time overflow"))?,
        payload_digest,
        predecessor_ref,
        event_digest: empty_sha256(),
    };
    event.event_digest = compute_controller_event_digest(&event)?;
    events.push(event);
    Ok(())
}

fn compute_controller_event_digest(
    event: &ControllerTranscriptEvent,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = event.clone();
    body.event_digest = empty_sha256();
    digest_serialized(&body, "controller transcript event")
}

fn verify_event_chain(
    proposal: &ToolCallProposal,
    events: &[ControllerTranscriptEvent],
) -> Result<(), EvaluationFault> {
    if events.is_empty() {
        return Err(machine_fault("controller transcript contains no events"));
    }
    for (index, event) in events.iter().enumerate() {
        let expected_predecessor = index
            .checked_sub(1)
            .and_then(|prior| events.get(prior))
            .map(|prior| prior.event_id.clone());
        if event.index != index as u64
            || event.call_ref != proposal.call_id
            || event.logical_time != proposal.invocation.initial_logical_time + index as u64
            || event.predecessor_ref != expected_predecessor
            || compute_controller_event_digest(event)? != event.event_digest
        {
            return Err(machine_fault("controller transcript event chain mismatch"));
        }
    }
    Ok(())
}

fn explicit_result_value(
    coordination: &CoordinationOutcome,
    invocation_result_digest: &ContentDigest,
) -> ProcedureValue {
    ProcedureValue::Record {
        fields: BTreeMap::from([
            (
                "invocation_ref".to_owned(),
                ProcedureValue::IdentityReference {
                    value: coordination.result.invocation_ref.clone(),
                },
            ),
            (
                "procedure_ref".to_owned(),
                ProcedureValue::IdentityReference {
                    value: coordination.result.procedure_ref.clone(),
                },
            ),
            (
                "invocation_result_digest".to_owned(),
                ProcedureValue::BytesDigest {
                    value: invocation_result_digest.clone(),
                },
            ),
            (
                "disposition".to_owned(),
                ProcedureValue::Text {
                    value: "returned".to_owned(),
                },
            ),
            (
                "output".to_owned(),
                coordination
                    .result
                    .output
                    .clone()
                    .unwrap_or(ProcedureValue::Null),
            ),
        ]),
    }
}
