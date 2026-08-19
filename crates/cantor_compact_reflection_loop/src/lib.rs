//! Pure contracts for one compact procedure call followed by model reflection.

#![forbid(unsafe_code)]

mod attention_reentry;
mod checkpoint_custody;
mod checkpoint_handle;
mod custody_query;
mod custody_query_measurement;
mod dispatch_checkpoint;
mod dispatch_lifecycle;
mod dual_transcript;
mod iterative;
mod lineage_index;
mod provider_protocol;
mod scripted_orchestrator;
mod scripted_stopped;
mod terminal_pending;
mod transcript_measurement;
mod transport_envelope;

pub use attention_reentry::{
    ATTENTION_REENTRY_FRAME_NONCLAIMS, ATTENTION_REENTRY_FRAME_PROFILE,
    ATTENTION_REENTRY_MEASUREMENT_NONCLAIMS, ATTENTION_REENTRY_MEASUREMENT_PROFILE,
    AttentionHeadKind, AttentionReentryFrame, AttentionReentryMeasurement,
    ReentryRequestByteMeasurement, compact_iterative_advance_request,
    compact_terminal_reflection_request, compile_attention_reentry_frame,
    generate_attention_reentry_measurement, pretty_attention_reentry_measurement_bytes,
    validate_attention_reentry_frame, validate_attention_reentry_measurement,
    validate_compact_attention_request,
};
pub use checkpoint_custody::{
    CHECKPOINT_CUSTODY_ENTRY_PROFILE, CHECKPOINT_CUSTODY_REGISTRY_NONCLAIMS,
    CHECKPOINT_CUSTODY_REGISTRY_PROFILE, CheckpointCustodyEntry, CheckpointCustodyRegistry,
    generate_scripted_checkpoint_custody_registry, new_checkpoint_custody_registry,
    pretty_checkpoint_custody_registry_bytes, register_checkpoint_custody,
    resolve_checkpoint_custody, resume_iteration_from_checkpoint_custody,
    resume_terminal_from_checkpoint_custody, validate_checkpoint_custody_registry,
    validate_scripted_checkpoint_custody_registry,
};
pub use checkpoint_handle::{
    DISPATCH_CHECKPOINT_HANDLE_MEASUREMENT_NONCLAIMS,
    DISPATCH_CHECKPOINT_HANDLE_MEASUREMENT_PROFILE, DISPATCH_CHECKPOINT_HANDLE_NONCLAIMS,
    DISPATCH_CHECKPOINT_HANDLE_PROFILE, DispatchCheckpointHandle, DispatchCheckpointHandleByteCase,
    DispatchCheckpointHandleMeasurement, compile_dispatch_checkpoint_handle,
    generate_dispatch_checkpoint_handle_measurement,
    pretty_dispatch_checkpoint_handle_measurement_bytes, validate_dispatch_checkpoint_handle,
    validate_dispatch_checkpoint_handle_against, validate_dispatch_checkpoint_handle_measurement,
};
pub use custody_query::{
    CHECKPOINT_CUSTODY_INSPECTION_PROFILE, CHECKPOINT_CUSTODY_QUERY_NONCLAIMS,
    CHECKPOINT_CUSTODY_QUERY_PROFILE, CHECKPOINT_CUSTODY_RESPONSE_PROFILE,
    CheckpointCustodyInspection, CheckpointCustodyOperation, CheckpointCustodyQuery,
    CheckpointCustodyResponse, CheckpointCustodyResult, dispatch_checkpoint_custody_query,
    pretty_checkpoint_custody_query_bytes, pretty_checkpoint_custody_response_bytes,
    validate_checkpoint_custody_query, validate_checkpoint_custody_response,
};
pub use custody_query_measurement::{
    CUSTODY_QUERY_SURFACE_MEASUREMENT_NONCLAIMS, CUSTODY_QUERY_SURFACE_MEASUREMENT_PROFILE,
    CustodyQuerySurfaceByteCase, CustodyQuerySurfaceMeasurement,
    generate_custody_query_surface_measurement, pretty_custody_query_surface_measurement_bytes,
    validate_custody_query_surface_measurement,
};
pub use dispatch_checkpoint::{
    DISPATCH_LIFECYCLE_CHECKPOINT_NONCLAIMS, DISPATCH_LIFECYCLE_CHECKPOINT_PROFILE,
    DispatchCheckpointNextOperation, DispatchLifecycleCheckpoint, DispatchResumeCase,
    SCRIPTED_DISPATCH_RESUME_CORPUS_NONCLAIMS, SCRIPTED_DISPATCH_RESUME_CORPUS_PROFILE,
    ScriptedDispatchResumeCorpus, compile_dispatch_lifecycle_checkpoint,
    generate_scripted_dispatch_resume_corpus, pretty_scripted_dispatch_resume_corpus_bytes,
    resume_iteration_fixture_checkpoint, resume_terminal_fixture_checkpoint,
    validate_dispatch_lifecycle_checkpoint, validate_scripted_dispatch_resume_corpus,
};
pub use dispatch_lifecycle::{
    EFFECTLESS_DISPATCH_NONCLAIMS, EFFECTLESS_DISPATCH_TRACE_PROFILE,
    EFFECTLESS_FIXTURE_DISPATCH_PROFILE, EffectlessDispatchPhase, EffectlessDispatchTrace,
    EffectlessFixtureDispatchRecord, SCRIPTED_EFFECTLESS_DISPATCH_RUN_NONCLAIMS,
    SCRIPTED_EFFECTLESS_DISPATCH_RUN_PROFILE, ScriptedEffectlessDispatchRun,
    admit_iteration_effectless_dispatch, admit_terminal_effectless_dispatch,
    generate_scripted_effectless_dispatch_run, prepare_effectless_dispatch,
    pretty_scripted_effectless_dispatch_run_bytes, record_effectless_fixture_dispatch,
    record_effectless_fixture_response, validate_effectless_dispatch_trace,
    validate_scripted_effectless_dispatch_run,
};
pub use dual_transcript::{
    AttentionTransportKind, AttentionTransportRecord, SCRIPTED_COMPACT_TRANSPORT_NONCLAIMS,
    SCRIPTED_COMPACT_TRANSPORT_PROFILE, ScriptedCompactTransportProjection,
    TerminalReflectionTransport, TransportByteAccount,
    generate_scripted_compact_transport_projection,
    pretty_scripted_compact_transport_projection_bytes, project_compact_transport,
    validate_scripted_compact_transport_projection,
};
pub use iterative::{
    DETERMINISTIC_DRIVE_MEASUREMENT_PROFILE, DETERMINISTIC_DRIVE_NONCLAIMS,
    DETERMINISTIC_DRIVE_PROFILE, DeterministicAdvanceRecord, DeterministicAdvanceSuccessor,
    DeterministicDriveMeasurement, DeterministicDriveResult, ITERATIVE_REPORT_NONCLAIMS,
    ITERATIVE_REPORT_PROFILE, IterationRecord, IterationSuccessor, IterativeReport,
    IterativeRunState, NextIterativeOperation, PolicyUsage, READY_PROJECTION_PROFILE,
    ReadyProjection, RunPolicy, StopReason, drive_bound_session,
    measure_deterministic_drive_result, normalize_deterministic_drive_result_json,
    project_ready_record, validate_deterministic_drive_measurement,
    validate_deterministic_drive_result, validate_iterative_report, validate_ready_projection,
    validate_run_policy,
};
pub use lineage_index::{
    PROVIDER_FREE_ATTENTION_LINEAGE_INDEX_NONCLAIMS, PROVIDER_FREE_ATTENTION_LINEAGE_INDEX_PROFILE,
    ProviderFreeAttentionLineageIndex, ProviderFreeCapabilityLedger,
    ProviderFreeLineageArtifactCommitment, ProviderFreeLineageArtifactKind,
    generate_provider_free_attention_lineage_index,
    pretty_provider_free_attention_lineage_index_bytes,
    validate_provider_free_attention_lineage_index,
};
pub use provider_protocol::{
    ITERATIVE_PROVIDER_NONCLAIMS, ITERATIVE_PROVIDER_PREFIX_PROFILE, IterativeProviderPhase,
    IterativeProviderPrefixProjection, admit_iterative_provider_iteration,
    iterative_advance_request, iterative_terminal_reflection_request,
    validate_iterative_provider_prefix, validate_provider_prefix_projection,
};
pub use scripted_orchestrator::{
    SCRIPTED_COMPLETE_RUN_NONCLAIMS, SCRIPTED_COMPLETE_RUN_PROFILE, SCRIPTED_PROVIDER_BASE,
    ScriptedCompleteRun, generate_scripted_complete_fixture, run_scripted_complete_iterative,
    validate_scripted_complete_run,
};
pub use scripted_stopped::{
    SCRIPTED_STOPPED_RUN_NONCLAIMS, SCRIPTED_STOPPED_RUN_PROFILE, ScriptedStoppedRun,
    generate_scripted_exhaustion_fixture, generate_scripted_tool_cap_fixture,
    resume_scripted_stopped, run_scripted_ready_stopped, validate_scripted_stopped_run,
};
pub use terminal_pending::{
    SCRIPTED_TERMINAL_PENDING_NONCLAIMS, SCRIPTED_TERMINAL_PENDING_PROFILE,
    ScriptedTerminalPendingRun, TERMINAL_PENDING_REPORT_NONCLAIMS, TERMINAL_PENDING_REPORT_PROFILE,
    TerminalReflectionPendingReport, admit_scripted_terminal_reflection,
    generate_scripted_terminal_pending_fixture, run_scripted_terminal_pending,
    scripted_terminal_reflection_response, validate_scripted_terminal_pending_run,
    validate_terminal_reflection_pending_report,
};
pub use transcript_measurement::{
    ITERATIVE_TRANSCRIPT_MEASUREMENT_NONCLAIMS, ITERATIVE_TRANSCRIPT_MEASUREMENT_PROFILE,
    IterativeTranscriptMeasurement, ProviderPassByteMeasurement,
    generate_iterative_transcript_measurement, pretty_iterative_transcript_measurement_bytes,
    validate_iterative_transcript_measurement,
};
pub use transport_envelope::{
    ATTENTION_TRANSPORT_ENVELOPE_NONCLAIMS, ATTENTION_TRANSPORT_ENVELOPE_PROFILE,
    AttentionTransportEnvelope, SCRIPTED_TRANSPORT_ENVELOPE_SET_NONCLAIMS,
    SCRIPTED_TRANSPORT_ENVELOPE_SET_PROFILE, ScriptedTransportEnvelopeSet,
    compile_iteration_transport_envelope, compile_terminal_transport_envelope,
    generate_scripted_transport_envelope_set, pretty_scripted_transport_envelope_set_bytes,
    project_transport_envelopes, validate_attention_transport_envelope,
    validate_iteration_transport_envelope_against, validate_scripted_transport_envelope_set,
    validate_terminal_transport_envelope_against,
};

use cantor_compact_coordination_mcp::{
    CompactCoordinationHandle, CompactCoordinationRecord, CompactCoordinationRegistry,
    CompactResponseStatus, CompactSessionCommand, CompactSessionResult, CompactSessionStatus,
    REGISTRY_PROFILE, apply_compact_coordination_command, new_compact_coordination_registry,
    validate_compact_coordination_registry,
};
use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    AuthorshipClass, AuthorshipLaneTemplate, ConsumedBudget, ContentDigest, InvocationBudget,
    InvocationDisposition, NegotiationStatus, ProcedureCandidate, ProcedureMessageKind,
    ProcedureValue, SemanticId, SensitivityClass, compute_candidate_source_digest,
    run_authorship_lane,
};
use cantor_procedure_tool::CoordinationToolContext;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

pub const REPORT_PROFILE: &str = "cantor-compact-procedure-reflection-report/0.1";
pub const TOOL_NAME: &str = "advance_attention_procedure";
pub const FINAL_STATEMENT: &str = "Cantor reached the referenced terminal procedure outcome; its digest is evidence, not external truth or effect authority.";
pub const REPORT_NONCLAIMS: [&str; 4] = [
    "no hidden-state or live-token insertion",
    "no external effect or semantic-truth claim",
    "no persistent or authenticated session",
    "no automatic remote or OneDrive access",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdvanceAttentionArguments {
    pub maximum_steps: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedAdvanceCall {
    pub assistant_message: Value,
    pub call_id: String,
    pub arguments: AdvanceAttentionArguments,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalObservation {
    pub observed_status: String,
    pub handle: CompactCoordinationHandle,
    pub record_json: String,
    pub outcome_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalProjection {
    pub profile: String,
    pub observed_status: String,
    pub session_id: SemanticId,
    pub sequence: u64,
    pub record_digest: ContentDigest,
    pub outcome_digest: ContentDigest,
    pub invocation_ref: SemanticId,
    pub procedure_ref: SemanticId,
    pub disposition: InvocationDisposition,
    pub consumed_budget: ConsumedBudget,
    pub step_count: usize,
    pub message_count: usize,
    pub terminal_return_count: usize,
    pub negotiation_status: Option<NegotiationStatus>,
    pub exact_record_available_via_read: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalOutput {
    pub observed_status: String,
    pub session_id: SemanticId,
    pub outcome_digest: ContentDigest,
    pub statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundSession {
    pub registry: CompactCoordinationRegistry,
    pub handle: CompactCoordinationHandle,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunReport {
    pub profile: String,
    pub status: String,
    pub base_url: String,
    pub model: String,
    pub context_path: String,
    pub context_sha256: String,
    pub session_id: SemanticId,
    pub maximum_steps: u64,
    pub first_request: Value,
    pub first_response: Value,
    pub terminal_observation: TerminalObservation,
    pub terminal_projection: TerminalProjection,
    pub reflection_request: Value,
    pub reflection_response: Value,
    pub final_output: FinalOutput,
    pub private_reasoning_recorded: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportVerification {
    pub profile: String,
    pub status: String,
    pub model: String,
    pub session_id: SemanticId,
    pub outcome_digest: ContentDigest,
    pub compact_registry_valid: bool,
    pub reflection_reconstructed: bool,
    pub private_reasoning_absent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReportInspection {
    pub profile: String,
    pub status: String,
    pub model: String,
    pub session_id: SemanticId,
    pub maximum_steps: u64,
    pub outcome_digest: ContentDigest,
    pub record_digest: ContentDigest,
    pub statement: String,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransportMeasurement {
    pub profile: String,
    pub fixture: String,
    pub maximum_steps: u64,
    pub context_json_bytes: usize,
    pub first_request_bytes: usize,
    pub tool_arguments_bytes: usize,
    pub terminal_handle_bytes: usize,
    pub terminal_record_bytes: usize,
    pub terminal_observation_bytes: usize,
    pub terminal_projection_bytes: usize,
    pub exact_observation_reflection_request_bytes: usize,
    pub reflection_request_bytes: usize,
    pub final_output_bytes: usize,
    pub complete_report_bytes: usize,
    pub reflection_request_reduction_basis_points: u64,
    pub terminal_projection_share_of_reflection_basis_points: u64,
    pub terminal_record_share_of_report_basis_points: u64,
    pub nonclaims: Vec<String>,
}

pub fn normalize_loopback_base_url(candidate: &str) -> Result<String, String> {
    let parsed = Url::parse(candidate).map_err(|error| format!("invalid base URL: {error}"))?;
    let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if parsed.scheme() != "http"
        || !loopback
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path().trim_end_matches('/') != "/v1"
    {
        return Err("base URL must be an unauthenticated loopback HTTP /v1 root".to_owned());
    }
    Ok(candidate.trim_end_matches('/').to_owned())
}

pub fn select_advertised_model(
    response: &Value,
    requested: Option<&str>,
) -> Result<String, String> {
    let models = response
        .get("data")
        .and_then(Value::as_array)
        .ok_or("model discovery omitted data array")?;
    let identifiers = models
        .iter()
        .map(|model| {
            model
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "advertised model omitted id".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if identifiers.iter().copied().collect::<BTreeSet<_>>().len() != identifiers.len() {
        return Err("model advertisement contains duplicate identities".to_owned());
    }
    if let Some(requested) = requested {
        if requested.is_empty() || !identifiers.contains(&requested) {
            return Err(format!("requested model is not advertised: {requested}"));
        }
        return Ok(requested.to_owned());
    }
    if identifiers.len() != 1 {
        return Err(format!(
            "expected one advertised model without --model, observed {}",
            identifiers.len()
        ));
    }
    Ok(identifiers[0].to_owned())
}

pub fn experimental_fixture_context_json() -> Result<String, String> {
    let sid = |value: &str| SemanticId::new(value).map_err(|fault| fault.to_string());
    let mut candidate: ProcedureCandidate = serde_json::from_str(include_str!(
        "../../cantor_core/tests/fixtures/cppe_two_process_candidate.json"
    ))
    .map_err(|error| format!("compiled fixture candidate is invalid: {error}"))?;
    candidate.candidate_id = sid("tool-candidate:compact-reflection-live-fixture")?;
    candidate.author_ref = sid("model-output:compact-reflection-live-fixture")?;
    candidate.provenance_refs = BTreeSet::from([sid("evidence:experimental-live-fixture")?]);
    candidate.source_digest = compute_candidate_source_digest(&candidate)
        .map_err(|fault| format!("fixture source digest failed: {fault}"))?;
    let template = AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:experimental-live-fixture")?]),
        validator_ref: sid("validator:experimental-live-fixture")?,
        policy_ref: sid("policy:experimental-live-fixture")?,
        aliases: BTreeSet::from(["experimental-compact-reflection-fixture".to_owned()]),
        permitted_invocation_context: "effectless-local-proof-only".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("invocation:experimental-live-fixture")?,
        caller_ref: sid("caller:experimental-live-fixture")?,
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "experimental local compact reflection".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:experimental-live-fixture")?,
        initial_logical_time: 20,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention")?,
        session_generation_ref: sid("session-generation:experimental-live-fixture")?,
        session_ref: sid("negotiation-session:experimental-live-fixture")?,
        session_purpose: "prove one local compact model tool model loop".to_owned(),
        frame_ref: sid("frame:experimental-live-fixture")?,
        frame_conditions: BTreeSet::from(["effectless".to_owned(), "experimental".to_owned()]),
        frame_constraints: BTreeSet::from(["local-only".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    };
    let lane = run_authorship_lane(&candidate, &template, &BTreeMap::new())
        .map_err(|fault| format!("fixture authorship lane failed: {fault}"))?;
    serde_json::to_string_pretty(&CoordinationToolContext::from(&lane))
        .map_err(|error| format!("fixture context serialization failed: {error}"))
}

pub fn generate_fixture_deterministic_drive_measurement()
-> Result<DeterministicDriveMeasurement, String> {
    let opening = open_bound_session(
        experimental_fixture_context_json()?,
        SemanticId::new("registry:deterministic-drive-measurement")
            .map_err(|fault| fault.to_string())?,
        SemanticId::new("session:deterministic-drive-measurement")
            .map_err(|fault| fault.to_string())?,
    )?;
    let result = drive_bound_session(
        &opening,
        RunPolicy {
            maximum_steps_per_call: 8,
            maximum_tool_calls: 8,
            maximum_provider_calls: 9,
            timeout_seconds: 120,
        },
    )?;
    measure_deterministic_drive_result(&result)
}

pub fn pretty_deterministic_drive_measurement_bytes(
    measurement: &DeterministicDriveMeasurement,
) -> Result<Vec<u8>, String> {
    validate_deterministic_drive_measurement(measurement)?;
    let mut bytes = serde_json::to_vec_pretty(measurement)
        .map_err(|error| format!("deterministic measurement serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn open_bound_session(
    context_json: String,
    registry_id: SemanticId,
    session_id: SemanticId,
) -> Result<BoundSession, String> {
    let registry = new_compact_coordination_registry(registry_id)?;
    let transition = apply_compact_coordination_command(
        &registry,
        CompactSessionCommand::Open {
            expected_registry_digest: registry.registry_digest.clone(),
            session_id,
            context_json,
        },
    );
    let handle = successful_state_handle(&transition.response)?;
    if handle.status != CompactSessionStatus::Ready {
        return Err("new compact session did not return a ready handle".to_owned());
    }
    Ok(BoundSession {
        registry: transition.successor,
        handle,
    })
}

pub fn advance_bound_session_terminal(
    session: &BoundSession,
    maximum_steps: u64,
) -> Result<(BoundSession, TerminalObservation), String> {
    if maximum_steps == 0 {
        return Err("maximum_steps must be positive".to_owned());
    }
    let transition = apply_compact_coordination_command(
        &session.registry,
        CompactSessionCommand::Advance {
            expected_registry_digest: session.handle.registry_digest.clone(),
            session_id: session.handle.session_id.clone(),
            expected_sequence: session.handle.sequence,
            expected_record_digest: session.handle.record_digest.clone(),
            maximum_steps,
        },
    );
    let handle = successful_state_handle(&transition.response)?;
    if handle.status != CompactSessionStatus::Terminal {
        return Err("P0 advancement did not reach terminal state".to_owned());
    }
    let read = apply_compact_coordination_command(
        &transition.successor,
        CompactSessionCommand::Read {
            expected_registry_digest: handle.registry_digest.clone(),
            session_id: handle.session_id.clone(),
        },
    );
    if read.successor != transition.successor {
        return Err("terminal READ unexpectedly changed the registry".to_owned());
    }
    let (read_handle, record_json, record_digest) = match read.response.result {
        Some(CompactSessionResult::Record {
            handle,
            record_json,
            record_digest,
        }) if read.response.status == CompactResponseStatus::Succeeded => {
            (handle, record_json, record_digest)
        }
        _ => return Err(compact_fault("terminal READ", &read.response)),
    };
    if read_handle != handle || record_digest != handle.record_digest {
        return Err("terminal READ identity differs from advancement handle".to_owned());
    }
    let record: CompactCoordinationRecord = serde_json::from_str(&record_json)
        .map_err(|error| format!("terminal record JSON is invalid: {error}"))?;
    if record.record_digest != record_digest
        || record.outcome.is_none()
        || record.checkpoint.is_some()
    {
        return Err("terminal record has an invalid digest or state shape".to_owned());
    }
    let outcome_digest = handle
        .outcome_digest
        .clone()
        .ok_or("terminal handle omitted outcome digest")?;
    Ok((
        BoundSession {
            registry: transition.successor,
            handle: handle.clone(),
        },
        TerminalObservation {
            observed_status: "terminal_outcome".to_owned(),
            handle,
            record_json,
            outcome_digest,
        },
    ))
}

pub fn project_terminal_observation(
    observation: &TerminalObservation,
) -> Result<TerminalProjection, String> {
    if observation.observed_status != "terminal_outcome"
        || observation.handle.status != CompactSessionStatus::Terminal
        || observation.handle.outcome_digest.as_ref() != Some(&observation.outcome_digest)
    {
        return Err(
            "terminal observation cannot be projected from its status or handle".to_owned(),
        );
    }
    let record: CompactCoordinationRecord = serde_json::from_str(&observation.record_json)
        .map_err(|error| format!("terminal record JSON is invalid: {error}"))?;
    if record.session_id != observation.handle.session_id
        || record.sequence != observation.handle.sequence
        || record.record_digest != observation.handle.record_digest
        || record.checkpoint.is_some()
    {
        return Err("terminal record differs from its projection handle".to_owned());
    }
    let outcome = record
        .outcome
        .as_ref()
        .ok_or("terminal record omitted outcome")?;
    Ok(TerminalProjection {
        profile: "cantor-verified-terminal-projection/0.1".to_owned(),
        observed_status: observation.observed_status.clone(),
        session_id: record.session_id,
        sequence: record.sequence,
        record_digest: record.record_digest,
        outcome_digest: observation.outcome_digest.clone(),
        invocation_ref: outcome.result.invocation_ref.clone(),
        procedure_ref: outcome.result.procedure_ref.clone(),
        disposition: outcome.result.disposition,
        consumed_budget: outcome.result.consumed_budget.clone(),
        step_count: outcome.steps.len(),
        message_count: outcome.messages.len(),
        terminal_return_count: outcome.terminal_returns.len(),
        negotiation_status: outcome
            .session_successor
            .as_ref()
            .map(|session| session.status),
        exact_record_available_via_read: true,
    })
}

pub fn first_request(model: &str, prompt: &str, maximum_steps: u64) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Call advance_attention_procedure exactly once with the required quota. Do not answer the subject yet. The host retains the signed context and will return the exact terminal result for a separate reflection pass."
            },
            {"role": "user", "content": prompt}
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": TOOL_NAME,
                "description": "Advance the host-bound Cantor attention procedure to its terminal result.",
                "parameters": {
                    "type": "object",
                    "properties": {"maximum_steps": {"type": "integer", "const": maximum_steps}},
                    "required": ["maximum_steps"],
                    "additionalProperties": false
                }
            }
        }],
        "tool_choice": "required",
        "parallel_tool_calls": false,
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 256
    })
}

pub fn extract_advance_call(
    response: &Value,
    expected_maximum_steps: u64,
) -> Result<ParsedAdvanceCall, String> {
    let choice = single_choice(response)?;
    if choice.get("finish_reason").and_then(Value::as_str) != Some("tool_calls") {
        return Err("first pass did not finish with tool_calls".to_owned());
    }
    let message = choice.get("message").ok_or("first pass omitted message")?;
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err("first pass message is not assistant-authored".to_owned());
    }
    if message
        .get("content")
        .is_some_and(|value| !value.is_null() && value.as_str() != Some(""))
    {
        return Err("first pass mixed public content with its tool call".to_owned());
    }
    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or("first pass omitted tool_calls")?;
    if calls.len() != 1 {
        return Err(format!("expected one tool call, observed {}", calls.len()));
    }
    let call = &calls[0];
    if call.pointer("/function/name").and_then(Value::as_str) != Some(TOOL_NAME) {
        return Err("first pass called the wrong tool".to_owned());
    }
    let call_id = call
        .get("id")
        .and_then(Value::as_str)
        .ok_or("tool call omitted id")?
        .to_owned();
    let encoded = call
        .pointer("/function/arguments")
        .ok_or("tool call omitted arguments")?;
    let value = if let Some(text) = encoded.as_str() {
        serde_json::from_str(text)
            .map_err(|error| format!("tool arguments are invalid JSON: {error}"))?
    } else if encoded.is_object() {
        encoded.clone()
    } else {
        return Err("tool arguments are not an encoded object".to_owned());
    };
    let arguments: AdvanceAttentionArguments = serde_json::from_value(value)
        .map_err(|error| format!("tool arguments violate the closed contract: {error}"))?;
    if arguments.maximum_steps != expected_maximum_steps {
        return Err("tool call changed the host-selected quota".to_owned());
    }
    Ok(ParsedAdvanceCall {
        assistant_message: json!({
            "role": "assistant",
            "content": message.get("content").cloned().unwrap_or(Value::Null),
            "tool_calls": [call.clone()]
        }),
        call_id,
        arguments,
    })
}

pub fn reflection_request(
    model: &str,
    prompt: &str,
    call: &ParsedAdvanceCall,
    projection: &TerminalProjection,
) -> Value {
    json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Import the exact terminal Cantor result from the tool message. Return only the required JSON. Preserve its session and outcome digests exactly, and do not treat the digest as external truth or effect authority."
            },
            {"role": "user", "content": prompt},
            call.assistant_message,
            {
                "role": "tool",
                "tool_call_id": call.call_id,
                "content": serde_json::to_string(projection).expect("projection serializes")
            },
            {"role": "user", "content": "Reflection checkpoint: acknowledge the imported terminal result now."}
        ],
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": false,
        "response_format": {
            "type": "json_object",
            "schema": final_schema(projection)
        },
        "chat_template_kwargs": {"enable_thinking": false},
        "temperature": 0,
        "max_tokens": 512
    })
}

pub fn extract_final_output(
    response: &Value,
    projection: &TerminalProjection,
) -> Result<FinalOutput, String> {
    let choice = single_choice(response)?;
    if choice.get("finish_reason").and_then(Value::as_str) != Some("stop") {
        return Err("reflection pass did not finish with stop".to_owned());
    }
    let message = choice
        .get("message")
        .ok_or("reflection pass omitted message")?;
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err("reflection message is not assistant-authored".to_owned());
    }
    if message
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|calls| !calls.is_empty())
    {
        return Err("reflection pass attempted another tool call".to_owned());
    }
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or("reflection pass omitted string content")?;
    let output: FinalOutput = serde_json::from_str(content)
        .map_err(|error| format!("reflection output violates JSON contract: {error}"))?;
    let expected = FinalOutput {
        observed_status: projection.observed_status.clone(),
        session_id: projection.session_id.clone(),
        outcome_digest: projection.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    if output != expected {
        return Err("reflection output changed the admitted terminal identity".to_owned());
    }
    Ok(output)
}

pub fn sanitize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut result = Map::new();
            for (key, item) in object {
                if !matches!(
                    key.as_str(),
                    "reasoning" | "reasoning_content" | "thinking" | "thinking_content"
                ) {
                    result.insert(key.clone(), sanitize(item));
                }
            }
            Value::Object(result)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize).collect()),
        _ => value.clone(),
    }
}

pub fn verify_report(report: &RunReport) -> Result<ReportVerification, String> {
    if report.profile != REPORT_PROFILE || report.status != "passed" {
        return Err("report profile or status is not recognized".to_owned());
    }
    if normalize_loopback_base_url(&report.base_url)? != report.base_url {
        return Err("report base URL is not canonical".to_owned());
    }
    if report.model.is_empty() || report.context_path.is_empty() {
        return Err("report model or historical context path is empty".to_owned());
    }
    if !is_lower_hex_sha256(&report.context_sha256) || !(1..=4096).contains(&report.maximum_steps) {
        return Err("report context digest or step quota is invalid".to_owned());
    }
    if report.private_reasoning_recorded
        || sanitize(&report.first_response) != report.first_response
        || sanitize(&report.reflection_response) != report.reflection_response
    {
        return Err("report contains or declares provider-private reasoning".to_owned());
    }
    let expected_nonclaims = REPORT_NONCLAIMS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if report.nonclaims != expected_nonclaims {
        return Err("report nonclaims differ from the compiled boundary".to_owned());
    }

    let prompt = report
        .first_request
        .pointer("/messages/1/content")
        .and_then(Value::as_str)
        .ok_or("report first request omitted the user prompt")?;
    if report.first_request != first_request(&report.model, prompt, report.maximum_steps) {
        return Err("report first request differs from deterministic reconstruction".to_owned());
    }
    let call = extract_advance_call(&report.first_response, report.maximum_steps)?;

    let observation = &report.terminal_observation;
    if observation.observed_status != "terminal_outcome"
        || observation.handle.status != CompactSessionStatus::Terminal
        || observation.handle.session_id != report.session_id
        || observation.handle.outcome_digest.as_ref() != Some(&observation.outcome_digest)
    {
        return Err("terminal observation identity or status is invalid".to_owned());
    }
    let record: CompactCoordinationRecord = serde_json::from_str(&observation.record_json)
        .map_err(|error| format!("terminal record JSON is invalid: {error}"))?;
    if record.session_id != report.session_id
        || record.sequence != observation.handle.sequence
        || record.record_digest != observation.handle.record_digest
        || record.checkpoint.is_some()
        || record.outcome.is_none()
    {
        return Err("terminal record differs from its report handle".to_owned());
    }
    let registry = CompactCoordinationRegistry {
        profile: REGISTRY_PROFILE.to_owned(),
        registry_id: observation.handle.registry_id.clone(),
        generation: observation.handle.sequence,
        sessions: BTreeMap::from([(record.session_id.clone(), record)]),
        registry_digest: observation.handle.registry_digest.clone(),
    };
    validate_compact_coordination_registry(&registry)
        .map_err(|error| format!("reconstructed terminal registry is invalid: {error}"))?;
    let inspected = apply_compact_coordination_command(
        &registry,
        CompactSessionCommand::Inspect {
            expected_registry_digest: observation.handle.registry_digest.clone(),
            session_id: report.session_id.clone(),
        },
    );
    let inspected_handle = successful_state_handle(&inspected.response)?;
    if inspected.successor != registry || inspected_handle != observation.handle {
        return Err("terminal handle differs from reconstructed registry inspection".to_owned());
    }

    let projection = project_terminal_observation(observation)?;
    if projection != report.terminal_projection {
        return Err("terminal projection differs from exact record derivation".to_owned());
    }

    let expected_reflection = reflection_request(&report.model, prompt, &call, &projection);
    if report.reflection_request != expected_reflection {
        return Err("reflection request differs from deterministic reconstruction".to_owned());
    }
    let final_output = extract_final_output(&report.reflection_response, &projection)?;
    if final_output != report.final_output {
        return Err("recorded final output differs from admitted reflection response".to_owned());
    }
    Ok(ReportVerification {
        profile: "cantor-compact-procedure-reflection-verification/0.1".to_owned(),
        status: "verified".to_owned(),
        model: report.model.clone(),
        session_id: report.session_id.clone(),
        outcome_digest: observation.outcome_digest.clone(),
        compact_registry_valid: true,
        reflection_reconstructed: true,
        private_reasoning_absent: true,
    })
}

pub fn inspect_report(report: &RunReport) -> Result<ReportInspection, String> {
    let verification = verify_report(report)?;
    Ok(ReportInspection {
        profile: "cantor-compact-procedure-reflection-inspection/0.1".to_owned(),
        status: verification.status,
        model: report.model.clone(),
        session_id: report.session_id.clone(),
        maximum_steps: report.maximum_steps,
        outcome_digest: report.terminal_observation.outcome_digest.clone(),
        record_digest: report.terminal_observation.handle.record_digest.clone(),
        statement: report.final_output.statement.clone(),
        authority: "internally_consistent_evidence_not_external_truth_or_effect_authority"
            .to_owned(),
    })
}

pub fn generate_fixture_transport_measurement() -> Result<TransportMeasurement, String> {
    let context_json = experimental_fixture_context_json()?;
    let session_id = SemanticId::new("session:compact-reflection-measurement")
        .map_err(|fault| fault.to_string())?;
    let session = open_bound_session(
        context_json.clone(),
        SemanticId::new("registry:compact-reflection-measurement")
            .map_err(|fault| fault.to_string())?,
        session_id.clone(),
    )?;
    let model = "fixture-tool-model";
    let prompt = "Run the measured bound procedure and reflect over its terminal identity.";
    let maximum_steps = 64;
    let initial_request = first_request(model, prompt, maximum_steps);
    let tool_arguments = AdvanceAttentionArguments { maximum_steps };
    let initial_response = json!({
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call-measurement-1",
                    "type": "function",
                    "function": {
                        "name": TOOL_NAME,
                        "arguments": serde_json::to_string(&tool_arguments)
                            .expect("tool arguments serialize")
                    }
                }]
            }
        }]
    });
    let call = extract_advance_call(&initial_response, maximum_steps)?;
    let (_, observation) = advance_bound_session_terminal(&session, maximum_steps)?;
    let projection = project_terminal_observation(&observation)?;
    let later_request = reflection_request(model, prompt, &call, &projection);
    let final_output = FinalOutput {
        observed_status: observation.observed_status.clone(),
        session_id: observation.handle.session_id.clone(),
        outcome_digest: observation.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    let later_response = json!({
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": serde_json::to_string(&final_output).expect("final output serializes")
            }
        }]
    });
    let report = RunReport {
        profile: REPORT_PROFILE.to_owned(),
        status: "passed".to_owned(),
        base_url: "http://127.0.0.1:8081/v1".to_owned(),
        model: model.to_owned(),
        context_path: "fixture://experimental-compact-reflection-context".to_owned(),
        context_sha256: sha256_hex(context_json.as_bytes()),
        session_id,
        maximum_steps,
        first_request: initial_request.clone(),
        first_response: initial_response,
        terminal_observation: observation.clone(),
        terminal_projection: projection.clone(),
        reflection_request: later_request.clone(),
        reflection_response: later_response,
        final_output: final_output.clone(),
        private_reasoning_recorded: false,
        nonclaims: REPORT_NONCLAIMS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    };
    verify_report(&report)?;

    let terminal_record_bytes = observation.record_json.len();
    let mut exact_observation_request = later_request.clone();
    exact_observation_request["messages"][3]["content"] =
        json!(serde_json::to_string(&observation).expect("terminal observation serializes"));
    let exact_observation_reflection_request_bytes =
        compact_json_bytes(&exact_observation_request)?;
    let reflection_request_bytes = compact_json_bytes(&later_request)?;
    let complete_report_bytes = compact_json_bytes(&report)?;
    let measurement = TransportMeasurement {
        profile: "cantor-compact-reflection-transport-measurement/0.2".to_owned(),
        fixture: "experimental_compact_reflection_context_v2".to_owned(),
        maximum_steps,
        context_json_bytes: context_json.len(),
        first_request_bytes: compact_json_bytes(&initial_request)?,
        tool_arguments_bytes: compact_json_bytes(&tool_arguments)?,
        terminal_handle_bytes: compact_json_bytes(&observation.handle)?,
        terminal_record_bytes,
        terminal_observation_bytes: compact_json_bytes(&observation)?,
        terminal_projection_bytes: compact_json_bytes(&projection)?,
        exact_observation_reflection_request_bytes,
        reflection_request_bytes,
        final_output_bytes: compact_json_bytes(&final_output)?,
        complete_report_bytes,
        reflection_request_reduction_basis_points: reduction_basis_points(
            exact_observation_reflection_request_bytes,
            reflection_request_bytes,
        )?,
        terminal_projection_share_of_reflection_basis_points: share_basis_points(
            compact_json_bytes(&projection)?,
            reflection_request_bytes,
        )?,
        terminal_record_share_of_report_basis_points: share_basis_points(
            terminal_record_bytes,
            complete_report_bytes,
        )?,
        nonclaims: vec![
            "structured UTF-8 JSON bytes are not model tokens".to_owned(),
            "measurement is not latency memory quality or general performance".to_owned(),
            "fixture execution invokes no provider effect or remote host".to_owned(),
        ],
    };
    validate_transport_measurement(&measurement)?;
    Ok(measurement)
}

pub fn validate_transport_measurement(measurement: &TransportMeasurement) -> Result<(), String> {
    if measurement.profile != "cantor-compact-reflection-transport-measurement/0.2"
        || measurement.fixture != "experimental_compact_reflection_context_v2"
        || measurement.maximum_steps != 64
    {
        return Err("transport measurement identity is invalid".to_owned());
    }
    let sizes = [
        measurement.context_json_bytes,
        measurement.first_request_bytes,
        measurement.tool_arguments_bytes,
        measurement.terminal_handle_bytes,
        measurement.terminal_record_bytes,
        measurement.terminal_observation_bytes,
        measurement.terminal_projection_bytes,
        measurement.exact_observation_reflection_request_bytes,
        measurement.reflection_request_bytes,
        measurement.final_output_bytes,
        measurement.complete_report_bytes,
    ];
    if sizes.contains(&0)
        || measurement.terminal_handle_bytes >= measurement.terminal_record_bytes
        || measurement.terminal_record_bytes >= measurement.terminal_observation_bytes
        || measurement.terminal_projection_bytes >= measurement.terminal_observation_bytes
        || measurement.reflection_request_bytes
            >= measurement.exact_observation_reflection_request_bytes
        || measurement.reflection_request_bytes >= measurement.complete_report_bytes
    {
        return Err("transport measurement size relationships are invalid".to_owned());
    }
    if measurement.reflection_request_reduction_basis_points
        != reduction_basis_points(
            measurement.exact_observation_reflection_request_bytes,
            measurement.reflection_request_bytes,
        )?
        || measurement.terminal_projection_share_of_reflection_basis_points
            != share_basis_points(
                measurement.terminal_projection_bytes,
                measurement.reflection_request_bytes,
            )?
        || measurement.terminal_record_share_of_report_basis_points
            != share_basis_points(
                measurement.terminal_record_bytes,
                measurement.complete_report_bytes,
            )?
        || measurement.nonclaims.len() != 3
    {
        return Err("transport measurement proportions or boundary are invalid".to_owned());
    }
    Ok(())
}

pub fn pretty_transport_measurement_bytes(
    measurement: &TransportMeasurement,
) -> Result<Vec<u8>, String> {
    validate_transport_measurement(measurement)?;
    let mut bytes = serde_json::to_vec_pretty(measurement)
        .map_err(|error| format!("measurement serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compact_json_bytes(value: &impl Serialize) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("measurement value serialization failed: {error}"))
}

fn share_basis_points(numerator: usize, denominator: usize) -> Result<u64, String> {
    if denominator == 0 {
        return Err("measurement denominator is zero".to_owned());
    }
    let scaled = (numerator as u128)
        .checked_mul(10_000)
        .ok_or("measurement proportion overflow")?
        / denominator as u128;
    u64::try_from(scaled).map_err(|_| "measurement proportion does not fit u64".to_owned())
}

fn reduction_basis_points(baseline: usize, reduced: usize) -> Result<u64, String> {
    if reduced > baseline {
        return Err("reduced measurement exceeds baseline".to_owned());
    }
    share_basis_points(baseline - reduced, baseline)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn successful_state_handle(
    response: &cantor_compact_coordination_mcp::CompactSessionResponse,
) -> Result<CompactCoordinationHandle, String> {
    match (&response.status, &response.result) {
        (CompactResponseStatus::Succeeded, Some(CompactSessionResult::State { handle })) => {
            Ok(handle.clone())
        }
        _ => Err(compact_fault("compact command", response)),
    }
}

fn compact_fault(
    stage: &str,
    response: &cantor_compact_coordination_mcp::CompactSessionResponse,
) -> String {
    let detail = response
        .fault
        .as_ref()
        .map(|fault| format!("{}: {}", fault.code, fault.message))
        .unwrap_or_else(|| "response omitted expected result".to_owned());
    format!("{stage} failed: {detail}")
}

fn single_choice(response: &Value) -> Result<&Map<String, Value>, String> {
    let choices = response
        .get("choices")
        .and_then(Value::as_array)
        .ok_or("provider response omitted choices")?;
    if choices.len() != 1 {
        return Err(format!(
            "expected one provider choice, observed {}",
            choices.len()
        ));
    }
    choices[0]
        .as_object()
        .ok_or_else(|| "provider choice is not an object".to_owned())
}

fn final_schema(projection: &TerminalProjection) -> Value {
    json!({
        "type": "object",
        "properties": {
            "observed_status": {"type": "string", "const": projection.observed_status},
            "session_id": {"type": "string", "const": projection.session_id.as_str()},
            "outcome_digest": {
                "type": "object",
                "properties": {
                    "algorithm": {"type": "string", "const": projection.outcome_digest.algorithm},
                    "value": {"type": "string", "const": projection.outcome_digest.value}
                },
                "required": ["algorithm", "value"],
                "additionalProperties": false
            },
            "statement": {"type": "string", "const": FINAL_STATEMENT}
        },
        "required": ["observed_status", "session_id", "outcome_digest", "statement"],
        "additionalProperties": false
    })
}
