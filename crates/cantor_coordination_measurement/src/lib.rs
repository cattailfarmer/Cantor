//! Deterministic structured-byte measurement for the resumable coordination tool.
//!
//! This crate measures compact JSON values. It does not measure tokens,
//! allocations, latency, throughput, network framing, or model behavior.

use std::collections::{BTreeMap, BTreeSet};

use cantor_coordination_mcp::{CoordinationMcpServer, TOOL_NAME};
use cantor_core::{
    AuthorshipClass, AuthorshipLaneEvidence, AuthorshipLaneTemplate, ContentDigest,
    InvocationBudget, ProcedureCandidate, ProcedureMessageKind, ProcedureValue, SemanticId,
    SensitivityClass, compute_candidate_source_digest, run_authorship_lane, sha256_bytes,
};
use cantor_procedure_tool::{
    CoordinationToolContext, CoordinationToolRequest, CoordinationToolResult,
    CoordinationToolStatus, execute_coordination_tool_request,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const MEASUREMENT_PROFILE: &str = "cantor-coordination-transport-measurement/0.1";
pub const FIXTURE_SOURCE: &str =
    "crates/cantor_core/tests/fixtures/cppe_two_process_candidate.json";
pub const QUOTA_SCHEDULES: [u64; 5] = [1, 2, 4, 8, 64];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticTransportMetrics {
    pub context_bytes: u64,
    pub begin_request_bytes: u64,
    pub begin_argument_bytes: u64,
    pub begin_response_bytes: u64,
    pub genesis_checkpoint_bytes: u64,
    pub tool_metadata_bytes: u64,
    pub input_schema_bytes: u64,
    pub output_schema_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleTransportMetrics {
    pub maximum_steps: u64,
    pub call_count: u64,
    pub advance_call_count: u64,
    pub steps_advanced: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub structured_bytes: u64,
    pub maximum_request_bytes: u64,
    pub maximum_response_bytes: u64,
    pub checkpoint_samples: u64,
    pub minimum_checkpoint_bytes: u64,
    pub maximum_checkpoint_bytes: u64,
    pub aggregate_checkpoint_bytes: u64,
    pub repeated_context_bytes: u64,
    pub zero_byte_handle_upper_bound: u64,
    pub context_request_share_basis_points: u64,
    pub context_total_share_basis_points: u64,
    pub terminal_outcome_bytes: u64,
    pub terminal_outcome_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoordinationTransportMeasurement {
    pub profile: String,
    pub fixture_source: String,
    pub tool_name: String,
    pub expected_terminal_steps: u64,
    pub static_metrics: StaticTransportMetrics,
    pub schedules: Vec<ScheduleTransportMetrics>,
    pub findings: Vec<String>,
    pub decision: String,
    pub nonclaims: Vec<String>,
    pub report_digest: ContentDigest,
}

pub fn generate_measurement() -> Result<CoordinationTransportMeasurement, String> {
    let lane = measurement_lane()?;
    let context = CoordinationToolContext::from(&lane);
    let context_bytes = encoded_len(&context)?;
    let begin_request = CoordinationToolRequest::Begin {
        context: Box::new(context.clone()),
    };
    let begin_response = execute_coordination_tool_request(begin_request.clone());
    require_success(&begin_response.status, "BEGIN")?;
    let genesis = match begin_response.result.as_ref() {
        Some(CoordinationToolResult::Began { checkpoint }) => (**checkpoint).clone(),
        _ => return Err("BEGIN did not return a genesis checkpoint".to_owned()),
    };
    let tool = CoordinationMcpServer::tool_definition();
    let output_schema = tool
        .output_schema
        .as_ref()
        .ok_or_else(|| "coordination MCP tool is missing output schema".to_owned())?;
    let static_metrics = StaticTransportMetrics {
        context_bytes,
        begin_request_bytes: encoded_len(&begin_request)?,
        begin_argument_bytes: argument_len(&begin_request)?,
        begin_response_bytes: encoded_len(&begin_response)?,
        genesis_checkpoint_bytes: encoded_len(&genesis)?,
        tool_metadata_bytes: encoded_len(&tool)?,
        input_schema_bytes: encoded_len(&tool.input_schema)?,
        output_schema_bytes: encoded_len(output_schema)?,
    };
    let expected_terminal_steps = lane.coordination.steps.len() as u64;
    if expected_terminal_steps == 0
        || expected_terminal_steps != lane.coordination.result.consumed_budget.steps
    {
        return Err("uninterrupted fixture step accounting is not coherent".to_owned());
    }

    let mut schedules = Vec::with_capacity(QUOTA_SCHEDULES.len());
    for maximum_steps in QUOTA_SCHEDULES {
        schedules.push(measure_schedule(
            &lane,
            &context,
            &begin_request,
            &begin_response,
            &genesis,
            context_bytes,
            maximum_steps,
            expected_terminal_steps,
        )?);
    }
    let quota_one = &schedules[0];
    let quota_eight = &schedules[3];
    let quota_sixty_four = &schedules[4];
    let mut report = CoordinationTransportMeasurement {
        profile: MEASUREMENT_PROFILE.to_owned(),
        fixture_source: FIXTURE_SOURCE.to_owned(),
        tool_name: TOOL_NAME.to_owned(),
        expected_terminal_steps,
        static_metrics,
        findings: vec![
            format!(
                "quota one uses {} calls and {} structured bytes",
                quota_one.call_count, quota_one.structured_bytes
            ),
            format!(
                "quota eight uses {} calls and {} structured bytes",
                quota_eight.call_count, quota_eight.structured_bytes
            ),
            format!(
                "quota sixty-four uses {} calls and {} structured bytes",
                quota_sixty_four.call_count, quota_sixty_four.structured_bytes
            ),
            format!(
                "the zero-byte-handle ceiling ranges from {} to {} removable bytes across measured schedules",
                quota_sixty_four.zero_byte_handle_upper_bound,
                quota_one.zero_byte_handle_upper_bound
            ),
        ],
        schedules,
        decision: "measurement_only_no_registry_authority".to_owned(),
        nonclaims: vec![
            "structured JSON bytes are not model tokens or context-window usage".to_owned(),
            "no latency allocation RSS throughput or network framing was measured".to_owned(),
            "one checked fixture does not establish general-program performance".to_owned(),
            "the zero-byte-handle upper bound is not realizable registry savings".to_owned(),
            "no stateful registry persistence authentication provider or effect is authorized"
                .to_owned(),
        ],
        report_digest: empty_digest(),
    };
    report.report_digest = compute_report_digest(&report)?;
    validate_measurement(&report)?;
    Ok(report)
}

pub fn validate_measurement(report: &CoordinationTransportMeasurement) -> Result<(), String> {
    if report.profile != MEASUREMENT_PROFILE {
        return Err("measurement profile is not recognized".to_owned());
    }
    if report.fixture_source != FIXTURE_SOURCE || report.tool_name != TOOL_NAME {
        return Err("fixture source or tool identity changed".to_owned());
    }
    if report.expected_terminal_steps == 0 {
        return Err("expected terminal step count must be positive".to_owned());
    }
    if report.schedules.len() != QUOTA_SCHEDULES.len() {
        return Err("measurement must contain exactly five schedules".to_owned());
    }
    let expected_digest = compute_report_digest(report)?;
    if report.report_digest != expected_digest {
        return Err("measurement report digest mismatch".to_owned());
    }
    let context_bytes = report.static_metrics.context_bytes;
    if context_bytes == 0
        || report.static_metrics.begin_request_bytes == 0
        || report.static_metrics.begin_argument_bytes == 0
        || report.static_metrics.begin_response_bytes == 0
        || report.static_metrics.genesis_checkpoint_bytes == 0
        || report.static_metrics.tool_metadata_bytes == 0
        || report.static_metrics.input_schema_bytes == 0
        || report.static_metrics.output_schema_bytes == 0
    {
        return Err("static byte metric must be positive".to_owned());
    }
    let expected_terminal_digest = report
        .schedules
        .first()
        .ok_or_else(|| "measurement schedules are absent".to_owned())?
        .terminal_outcome_digest
        .clone();
    let expected_terminal_bytes = report.schedules[0].terminal_outcome_bytes;
    for (schedule, expected_quota) in report.schedules.iter().zip(QUOTA_SCHEDULES) {
        if schedule.maximum_steps != expected_quota {
            return Err("measurement quota order or identity changed".to_owned());
        }
        if schedule.steps_advanced != report.expected_terminal_steps {
            return Err(format!(
                "quota {} advanced {} steps; expected {}",
                schedule.maximum_steps, schedule.steps_advanced, report.expected_terminal_steps
            ));
        }
        if schedule.call_count != schedule.advance_call_count + 1 {
            return Err("schedule call arithmetic is inconsistent".to_owned());
        }
        if schedule.structured_bytes != schedule.request_bytes + schedule.response_bytes {
            return Err("schedule transfer arithmetic is inconsistent".to_owned());
        }
        if schedule.repeated_context_bytes != context_bytes * schedule.call_count {
            return Err("repeated context arithmetic is inconsistent".to_owned());
        }
        if schedule.zero_byte_handle_upper_bound
            != context_bytes * schedule.call_count.saturating_sub(1)
        {
            return Err("zero-byte handle ceiling arithmetic is inconsistent".to_owned());
        }
        if schedule.context_request_share_basis_points
            != basis_points(schedule.repeated_context_bytes, schedule.request_bytes)
            || schedule.context_total_share_basis_points
                != basis_points(schedule.repeated_context_bytes, schedule.structured_bytes)
        {
            return Err("context share arithmetic is inconsistent".to_owned());
        }
        if schedule.checkpoint_samples != schedule.advance_call_count
            || schedule.minimum_checkpoint_bytes == 0
            || schedule.maximum_checkpoint_bytes < schedule.minimum_checkpoint_bytes
            || schedule.aggregate_checkpoint_bytes < schedule.minimum_checkpoint_bytes
        {
            return Err("checkpoint sample arithmetic is inconsistent".to_owned());
        }
        if schedule.terminal_outcome_bytes != expected_terminal_bytes
            || schedule.terminal_outcome_digest != expected_terminal_digest
        {
            return Err("quota schedules did not produce one exact terminal outcome".to_owned());
        }
    }
    if report.decision != "measurement_only_no_registry_authority" {
        return Err("measurement cannot grant registry authority".to_owned());
    }
    Ok(())
}

pub fn pretty_measurement_bytes(
    report: &CoordinationTransportMeasurement,
) -> Result<Vec<u8>, String> {
    validate_measurement(report)?;
    let mut bytes = serde_json::to_vec_pretty(report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn measure_schedule(
    lane: &AuthorshipLaneEvidence,
    context: &CoordinationToolContext,
    begin_request: &CoordinationToolRequest,
    begin_response: &cantor_procedure_tool::CoordinationToolResponse,
    genesis: &cantor_core::CoordinationCheckpoint,
    context_bytes: u64,
    maximum_steps: u64,
    expected_terminal_steps: u64,
) -> Result<ScheduleTransportMetrics, String> {
    let mut checkpoint = genesis.clone();
    let mut request_bytes = argument_len(begin_request)?;
    let mut response_bytes = encoded_len(begin_response)?;
    let mut maximum_request_bytes = request_bytes;
    let mut maximum_response_bytes = response_bytes;
    let mut checkpoint_sizes = vec![encoded_len(genesis)?];
    let mut advance_call_count = 0_u64;
    let mut steps_advanced = 0_u64;
    let (terminal_outcome_bytes, terminal_outcome_digest) = loop {
        advance_call_count += 1;
        if advance_call_count > expected_terminal_steps + 2 {
            return Err("schedule exceeded bounded advance-call count".to_owned());
        }
        let request = CoordinationToolRequest::Advance {
            context: Box::new(context.clone()),
            checkpoint: Box::new(checkpoint),
            maximum_steps,
        };
        let current_request_bytes = argument_len(&request)?;
        let response = execute_coordination_tool_request(request);
        require_success(&response.status, "ADVANCE")?;
        let current_response_bytes = encoded_len(&response)?;
        request_bytes += current_request_bytes;
        response_bytes += current_response_bytes;
        maximum_request_bytes = maximum_request_bytes.max(current_request_bytes);
        maximum_response_bytes = maximum_response_bytes.max(current_response_bytes);
        let transition = match response.result {
            Some(CoordinationToolResult::Advanced { transition }) => *transition,
            _ => return Err("ADVANCE did not return a transition".to_owned()),
        };
        steps_advanced += transition.steps_advanced;
        match (transition.checkpoint, transition.outcome) {
            (Some(successor), None) => {
                checkpoint_sizes.push(encoded_len(&successor)?);
                checkpoint = successor;
            }
            (None, Some(outcome)) => {
                if outcome != lane.coordination {
                    return Err(
                        "schedule terminal outcome differs from uninterrupted lane".to_owned()
                    );
                }
                if outcome.steps.len() as u64 != outcome.result.consumed_budget.steps {
                    return Err(format!(
                        "terminal outcome retains {} steps but consumed budget reports {}",
                        outcome.steps.len(),
                        outcome.result.consumed_budget.steps
                    ));
                }
                let bytes = serde_json::to_vec(&outcome).map_err(|error| error.to_string())?;
                break (bytes.len() as u64, sha256_bytes(&bytes));
            }
            _ => return Err("transition must carry exactly one checkpoint or outcome".to_owned()),
        }
    };
    let call_count = advance_call_count + 1;
    if steps_advanced != expected_terminal_steps {
        return Err(format!(
            "quota {maximum_steps} reported {steps_advanced} steps; expected {expected_terminal_steps}"
        ));
    }
    let repeated_context_bytes = context_bytes * call_count;
    let structured_bytes = request_bytes + response_bytes;
    Ok(ScheduleTransportMetrics {
        maximum_steps,
        call_count,
        advance_call_count,
        steps_advanced,
        request_bytes,
        response_bytes,
        structured_bytes,
        maximum_request_bytes,
        maximum_response_bytes,
        checkpoint_samples: checkpoint_sizes.len() as u64,
        minimum_checkpoint_bytes: *checkpoint_sizes
            .iter()
            .min()
            .ok_or_else(|| "checkpoint samples are absent".to_owned())?,
        maximum_checkpoint_bytes: *checkpoint_sizes
            .iter()
            .max()
            .ok_or_else(|| "checkpoint samples are absent".to_owned())?,
        aggregate_checkpoint_bytes: checkpoint_sizes.iter().sum(),
        repeated_context_bytes,
        zero_byte_handle_upper_bound: context_bytes * call_count.saturating_sub(1),
        context_request_share_basis_points: basis_points(repeated_context_bytes, request_bytes),
        context_total_share_basis_points: basis_points(repeated_context_bytes, structured_bytes),
        terminal_outcome_bytes,
        terminal_outcome_digest,
    })
}

fn measurement_lane() -> Result<AuthorshipLaneEvidence, String> {
    run_authorship_lane(
        &measurement_candidate()?,
        &measurement_template()?,
        &BTreeMap::new(),
    )
    .map_err(|fault| fault.to_string())
}

fn measurement_candidate() -> Result<ProcedureCandidate, String> {
    let mut candidate: ProcedureCandidate = serde_json::from_str(include_str!(
        "../../cantor_core/tests/fixtures/cppe_two_process_candidate.json"
    ))
    .map_err(|error| error.to_string())?;
    candidate.candidate_id = sid("tool-candidate:coordination-measurement")?;
    candidate.author_ref = sid("model-output:coordination-measurement-author")?;
    candidate.provenance_refs = BTreeSet::from([sid("evidence:coordination-measurement")?]);
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).map_err(|fault| fault.to_string())?;
    Ok(candidate)
}

fn measurement_template() -> Result<AuthorshipLaneTemplate, String> {
    Ok(AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:coordination-measurement")?]),
        validator_ref: sid("validator:coordination-measurement")?,
        policy_ref: sid("policy:coordination-measurement")?,
        aliases: BTreeSet::from(["coordination-measurement".to_owned()]),
        permitted_invocation_context: "effectless-coordination-measurement".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("invocation:coordination-measurement")?,
        caller_ref: sid("caller:coordination-measurement")?,
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:coordination-measurement")?,
        initial_logical_time: 20,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention")?,
        session_generation_ref: sid("session-generation:coordination-measurement")?,
        session_ref: sid("session:coordination-measurement")?,
        session_purpose: "measure exact structured coordination transport".to_owned(),
        frame_ref: sid("frame:coordination-measurement")?,
        frame_conditions: BTreeSet::from(["effectless".to_owned()]),
        frame_constraints: BTreeSet::from(["provider-neutral".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    })
}

fn compute_report_digest(
    report: &CoordinationTransportMeasurement,
) -> Result<ContentDigest, String> {
    let mut unsigned = report.clone();
    unsigned.report_digest = empty_digest();
    let bytes = serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?;
    Ok(sha256_bytes(&bytes))
}

fn argument_len(request: &CoordinationToolRequest) -> Result<u64, String> {
    encoded_len(&json!({ "request": request }))
}

fn encoded_len<T: Serialize>(value: &T) -> Result<u64, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|error| error.to_string())
}

fn basis_points(numerator: u64, denominator: u64) -> u64 {
    numerator
        .saturating_mul(10_000)
        .checked_div(denominator)
        .unwrap_or(0)
}

fn require_success(status: &CoordinationToolStatus, operation: &str) -> Result<(), String> {
    if *status == CoordinationToolStatus::Succeeded {
        Ok(())
    } else {
        Err(format!(
            "{operation} returned non-success status {status:?}"
        ))
    }
}

fn sid(value: &str) -> Result<SemanticId, String> {
    SemanticId::new(value).map_err(|fault| fault.to_string())
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}
