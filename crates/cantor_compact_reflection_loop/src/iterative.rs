//! Strict effectless forms for the bounded iterative attention loop.

use cantor_compact_coordination_mcp::{
    CompactCoordinationHandle, CompactCoordinationRegistry, CompactResponseStatus,
    CompactSessionResponse, CompactSessionResult, CompactSessionStatus,
    validate_compact_coordination_registry,
};
use cantor_core::{ContentDigest, SemanticId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    FINAL_STATEMENT, FinalOutput, TerminalObservation, TerminalProjection,
    project_terminal_observation,
};

pub const READY_PROJECTION_PROFILE: &str = "cantor-ready-projection/0.1";
pub const ITERATIVE_REPORT_PROFILE: &str = "cantor-iterative-attention-procedure-loop-report/0.1";
pub const ITERATIVE_REPORT_NONCLAIMS: [&str; 5] = [
    "structural validation is not complete causal replay",
    "no hidden-state or live-token insertion",
    "no external effect or semantic-truth claim",
    "no persistent or authenticated session",
    "no automatic remote or OneDrive access",
];

const MAX_STEPS_PER_CALL: u64 = 4_096;
const MAX_TOOL_CALLS: u32 = 64;
const MAX_PROVIDER_CALLS: u32 = 129;
const MAX_TIMEOUT_SECONDS: u64 = 3_600;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunPolicy {
    pub maximum_steps_per_call: u64,
    pub maximum_tool_calls: u32,
    pub maximum_provider_calls: u32,
    pub timeout_seconds: u64,
}

impl Default for RunPolicy {
    fn default() -> Self {
        Self {
            maximum_steps_per_call: 8,
            maximum_tool_calls: 8,
            maximum_provider_calls: 17,
            timeout_seconds: 120,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NextIterativeOperation {
    AdvanceAttentionProcedure,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadyProjection {
    pub profile: String,
    pub session_id: SemanticId,
    pub sequence: u64,
    pub record_digest: ContentDigest,
    pub checkpoint_digest: ContentDigest,
    pub handle_digest: ContentDigest,
    pub slice_index: u64,
    pub step_count: usize,
    pub message_count: usize,
    pub pending_reactivation_count: usize,
    pub state_is_terminal: bool,
    pub exact_state_under_host_custody: bool,
    pub next_legal_operation: NextIterativeOperation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IterationSuccessor {
    Ready { projection: ReadyProjection },
    Terminal { projection: TerminalProjection },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IterationRecord {
    pub iteration_index: u32,
    pub predecessor_handle: CompactCoordinationHandle,
    pub request: Value,
    pub sanitized_response: Value,
    pub call_id: String,
    pub maximum_steps: u64,
    pub compact_response: CompactSessionResponse,
    pub successor: IterationSuccessor,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IterativeRunState {
    Complete,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    ToolCallCap,
    ProviderCallCap,
    Timeout,
    ProviderProtocolFault,
    CompactFault,
    ProjectionFault,
    RestartUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyUsage {
    pub tool_calls: u32,
    pub provider_calls: u32,
    pub elapsed_milliseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IterativeReport {
    pub profile: String,
    pub status: IterativeRunState,
    pub policy: RunPolicy,
    pub usage: PolicyUsage,
    pub base_url: String,
    pub model: String,
    pub session_id: SemanticId,
    pub opening_handle: CompactCoordinationHandle,
    pub iterations: Vec<IterationRecord>,
    pub terminal_observation: Option<TerminalObservation>,
    pub terminal_projection: Option<TerminalProjection>,
    pub final_output: Option<FinalOutput>,
    pub reentry_handle: Option<CompactCoordinationHandle>,
    pub reentry_available: Option<bool>,
    pub stop_reason: Option<StopReason>,
    pub private_reasoning_recorded: bool,
    pub nonclaims: Vec<String>,
}

pub fn validate_run_policy(policy: &RunPolicy) -> Result<(), String> {
    if !(1..=MAX_STEPS_PER_CALL).contains(&policy.maximum_steps_per_call) {
        return Err("maximum_steps_per_call is outside 1..=4096".to_owned());
    }
    if !(1..=MAX_TOOL_CALLS).contains(&policy.maximum_tool_calls) {
        return Err("maximum_tool_calls is outside 1..=64".to_owned());
    }
    if !(1..=MAX_PROVIDER_CALLS).contains(&policy.maximum_provider_calls) {
        return Err("maximum_provider_calls is outside 1..=129".to_owned());
    }
    if policy.maximum_provider_calls < policy.maximum_tool_calls {
        return Err("provider-call cap cannot be below tool-call cap".to_owned());
    }
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&policy.timeout_seconds) {
        return Err("timeout_seconds is outside 1..=3600".to_owned());
    }
    Ok(())
}

pub fn project_ready_record(
    registry: &CompactCoordinationRegistry,
    handle: &CompactCoordinationHandle,
) -> Result<ReadyProjection, String> {
    validate_compact_coordination_registry(registry)?;
    if handle.registry_id != registry.registry_id
        || handle.registry_digest != registry.registry_digest
    {
        return Err("ready handle does not identify the admitted registry".to_owned());
    }
    let record = registry
        .sessions
        .get(&handle.session_id)
        .ok_or_else(|| "ready handle session is absent from the registry".to_owned())?;
    if handle.status != CompactSessionStatus::Ready {
        return Err("ready projection requires a READY handle".to_owned());
    }
    if handle.session_id != record.session_id
        || handle.sequence != record.sequence
        || handle.record_digest != record.record_digest
    {
        return Err("ready handle and retained record identity differ".to_owned());
    }
    if record.outcome.is_some() {
        return Err("ready record cannot contain a terminal outcome".to_owned());
    }
    let checkpoint = record
        .checkpoint
        .as_ref()
        .ok_or_else(|| "ready record is missing its checkpoint".to_owned())?;
    if handle.checkpoint_digest.as_ref() != Some(&checkpoint.checkpoint_digest)
        || handle.outcome_digest.is_some()
    {
        return Err("ready handle checkpoint identity differs from record".to_owned());
    }
    let projection = ReadyProjection {
        profile: READY_PROJECTION_PROFILE.to_owned(),
        session_id: handle.session_id.clone(),
        sequence: handle.sequence,
        record_digest: handle.record_digest.clone(),
        checkpoint_digest: checkpoint.checkpoint_digest.clone(),
        handle_digest: handle.handle_digest.clone(),
        slice_index: checkpoint.slice_index,
        step_count: checkpoint.steps.len(),
        message_count: checkpoint.messages.len(),
        pending_reactivation_count: checkpoint.pending_reactivation_refs.len(),
        state_is_terminal: false,
        exact_state_under_host_custody: true,
        next_legal_operation: NextIterativeOperation::AdvanceAttentionProcedure,
    };
    validate_ready_projection(&projection, handle)?;
    Ok(projection)
}

pub fn validate_ready_projection(
    projection: &ReadyProjection,
    handle: &CompactCoordinationHandle,
) -> Result<(), String> {
    if projection.profile != READY_PROJECTION_PROFILE {
        return Err("ready projection profile is not recognized".to_owned());
    }
    if handle.status != CompactSessionStatus::Ready
        || projection.session_id != handle.session_id
        || projection.sequence != handle.sequence
        || projection.record_digest != handle.record_digest
        || Some(&projection.checkpoint_digest) != handle.checkpoint_digest.as_ref()
        || projection.handle_digest != handle.handle_digest
        || handle.outcome_digest.is_some()
    {
        return Err("ready projection does not match its exact handle".to_owned());
    }
    if projection.state_is_terminal || !projection.exact_state_under_host_custody {
        return Err("ready projection misstates nonterminal host custody".to_owned());
    }
    Ok(())
}

pub fn validate_iterative_report(report: &IterativeReport) -> Result<(), String> {
    if report.profile != ITERATIVE_REPORT_PROFILE {
        return Err("iterative report profile is not recognized".to_owned());
    }
    validate_run_policy(&report.policy)?;
    if report.private_reasoning_recorded {
        return Err("iterative report cannot retain private reasoning".to_owned());
    }
    if report.nonclaims
        != ITERATIVE_REPORT_NONCLAIMS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    {
        return Err("iterative report nonclaims differ from the compiled set".to_owned());
    }
    if report.opening_handle.status != CompactSessionStatus::Ready
        || report.opening_handle.session_id != report.session_id
        || report.base_url.trim().is_empty()
        || report.model.trim().is_empty()
    {
        return Err("iterative report opening identity is invalid".to_owned());
    }
    if report.usage.tool_calls as usize != report.iterations.len()
        || report.usage.tool_calls > report.policy.maximum_tool_calls
        || report.usage.provider_calls > report.policy.maximum_provider_calls
        || report.usage.provider_calls < report.usage.tool_calls
    {
        return Err("iterative report policy usage is inconsistent".to_owned());
    }

    let mut expected_predecessor = &report.opening_handle;
    for (index, iteration) in report.iterations.iter().enumerate() {
        if usize::try_from(iteration.iteration_index).ok() != Some(index)
            || &iteration.predecessor_handle != expected_predecessor
            || iteration.maximum_steps != report.policy.maximum_steps_per_call
            || iteration.call_id.trim().is_empty()
            || iteration.compact_response.status != CompactResponseStatus::Succeeded
        {
            return Err("iterative record identity policy or response is invalid".to_owned());
        }
        let successor_handle = response_handle(&iteration.compact_response)?;
        match &iteration.successor {
            IterationSuccessor::Ready { projection } => {
                validate_ready_projection(projection, successor_handle)?;
            }
            IterationSuccessor::Terminal { projection } => {
                if successor_handle.status != CompactSessionStatus::Terminal
                    || projection.session_id != successor_handle.session_id
                    || projection.sequence != successor_handle.sequence
                    || projection.record_digest != successor_handle.record_digest
                    || Some(&projection.outcome_digest) != successor_handle.outcome_digest.as_ref()
                {
                    return Err("terminal successor does not match its exact handle".to_owned());
                }
            }
        }
        expected_predecessor = successor_handle;
    }

    match report.status {
        IterativeRunState::Complete => validate_complete_report(report, expected_predecessor),
        IterativeRunState::Stopped => validate_stopped_report(report, expected_predecessor),
    }
}

fn response_handle(
    response: &CompactSessionResponse,
) -> Result<&CompactCoordinationHandle, String> {
    match response.result.as_ref() {
        Some(CompactSessionResult::State { handle }) => Ok(handle),
        Some(CompactSessionResult::Record { .. }) => {
            Err("iteration ADVANCE response cannot be a READ record".to_owned())
        }
        None => Err("successful iteration response is missing its handle".to_owned()),
    }
}

fn validate_complete_report(
    report: &IterativeReport,
    head: &CompactCoordinationHandle,
) -> Result<(), String> {
    let observation = report
        .terminal_observation
        .as_ref()
        .ok_or_else(|| "complete report is missing terminal observation".to_owned())?;
    let projection = report
        .terminal_projection
        .as_ref()
        .ok_or_else(|| "complete report is missing terminal projection".to_owned())?;
    let output = report
        .final_output
        .as_ref()
        .ok_or_else(|| "complete report is missing final output".to_owned())?;
    let derived_projection = project_terminal_observation(observation)?;
    let recorded_successor = report.iterations.last().map(|record| &record.successor);
    if report.iterations.is_empty()
        || head.status != CompactSessionStatus::Terminal
        || report.reentry_handle.is_some()
        || report.reentry_available.is_some()
        || report.stop_reason.is_some()
        || report.usage.provider_calls != report.usage.tool_calls.saturating_add(1)
        || observation.handle != *head
        || projection != &derived_projection
        || !matches!(
            recorded_successor,
            Some(IterationSuccessor::Terminal { projection: successor }) if successor == projection
        )
        || output.session_id != report.session_id
        || output.outcome_digest != projection.outcome_digest
        || output.observed_status != projection.observed_status
        || output.statement != FINAL_STATEMENT
    {
        return Err("complete report terminal identity or exclusivity is invalid".to_owned());
    }
    Ok(())
}

fn validate_stopped_report(
    report: &IterativeReport,
    head: &CompactCoordinationHandle,
) -> Result<(), String> {
    let reentry = report
        .reentry_handle
        .as_ref()
        .ok_or_else(|| "stopped report is missing its reentry handle".to_owned())?;
    let reentry_available = report
        .reentry_available
        .ok_or_else(|| "stopped report is missing reentry availability".to_owned())?;
    if report.stop_reason.is_none()
        || report.terminal_observation.is_some()
        || report.terminal_projection.is_some()
        || report.final_output.is_some()
        || head.status != CompactSessionStatus::Ready
        || reentry != head
    {
        return Err("stopped report state or exclusivity is invalid".to_owned());
    }
    if (report.stop_reason == Some(StopReason::RestartUnavailable)) == reentry_available {
        return Err("stop reason and reentry availability contradict".to_owned());
    }
    if report.stop_reason == Some(StopReason::Timeout)
        && report.usage.elapsed_milliseconds < report.policy.timeout_seconds.saturating_mul(1_000)
    {
        return Err("timeout stop precedes the declared timeout boundary".to_owned());
    }
    Ok(())
}
