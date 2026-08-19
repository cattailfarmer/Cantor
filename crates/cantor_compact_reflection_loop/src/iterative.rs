//! Strict effectless forms for the bounded iterative attention loop.

use std::collections::BTreeSet;

use cantor_compact_coordination_mcp::{
    CompactCoordinationHandle, CompactCoordinationRegistry, CompactResponseStatus,
    CompactSessionCommand, CompactSessionOperation, CompactSessionResponse, CompactSessionResult,
    CompactSessionStatus, HANDLE_PROFILE, RESPONSE_PROFILE, apply_compact_coordination_command,
    validate_compact_coordination_registry,
};
use cantor_core::{ContentDigest, SemanticId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    BoundSession, FINAL_STATEMENT, FinalOutput, TerminalObservation, TerminalProjection,
    project_terminal_observation,
};

pub const READY_PROJECTION_PROFILE: &str = "cantor-ready-projection/0.1";
pub const ITERATIVE_REPORT_PROFILE: &str = "cantor-iterative-attention-procedure-loop-report/0.1";
pub const DETERMINISTIC_DRIVE_PROFILE: &str = "cantor-deterministic-attention-procedure-drive/0.1";
pub const DETERMINISTIC_DRIVE_MEASUREMENT_PROFILE: &str =
    "cantor-deterministic-attention-procedure-drive-measurement/0.1";
pub const ITERATIVE_REPORT_NONCLAIMS: [&str; 5] = [
    "structural validation is not complete causal replay",
    "no hidden-state or live-token insertion",
    "no external effect or semantic-truth claim",
    "no persistent or authenticated session",
    "no automatic remote or OneDrive access",
];
pub const DETERMINISTIC_DRIVE_NONCLAIMS: [&str; 6] = [
    "no provider or model call was performed",
    "structural replay is not complete causal re-execution",
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeterministicAdvanceSuccessor {
    Ready { projection: ReadyProjection },
    Terminal { handle: CompactCoordinationHandle },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeterministicAdvanceRecord {
    pub iteration_index: u32,
    pub predecessor_handle: CompactCoordinationHandle,
    pub maximum_steps: u64,
    pub compact_response: CompactSessionResponse,
    pub successor: DeterministicAdvanceSuccessor,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeterministicDriveResult {
    pub profile: String,
    pub status: IterativeRunState,
    pub policy: RunPolicy,
    pub opening_handle: CompactCoordinationHandle,
    pub advances: Vec<DeterministicAdvanceRecord>,
    pub successor_registry: CompactCoordinationRegistry,
    pub terminal_observation: Option<TerminalObservation>,
    pub stopped_head: Option<CompactCoordinationHandle>,
    pub reentry_available: Option<bool>,
    pub stop_reason: Option<StopReason>,
    pub fault_response: Option<CompactSessionResponse>,
    pub fault_message: Option<String>,
    pub private_reasoning_recorded: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeterministicDriveMeasurement {
    pub profile: String,
    pub drive_profile: String,
    pub status: IterativeRunState,
    pub maximum_steps_per_call: u64,
    pub maximum_tool_calls: u32,
    pub advance_count: usize,
    pub ready_projection_count: usize,
    pub opening_handle_bytes: usize,
    pub advance_records_bytes: usize,
    pub ready_projection_bytes: usize,
    pub terminal_projection_bytes: usize,
    pub terminal_observation_bytes: usize,
    pub successor_registry_bytes: usize,
    pub normalized_drive_result_bytes: usize,
    pub model_facing_projection_bytes: usize,
    pub model_facing_share_of_result_basis_points: u64,
    pub byte_basis: String,
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
    if policy.maximum_provider_calls < policy.maximum_tool_calls.saturating_add(1) {
        return Err("provider-call cap must reserve one terminal reflection call".to_owned());
    }
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&policy.timeout_seconds) {
        return Err("timeout_seconds is outside 1..=3600".to_owned());
    }
    Ok(())
}

pub fn drive_bound_session(
    opening: &BoundSession,
    policy: RunPolicy,
) -> Result<DeterministicDriveResult, String> {
    validate_run_policy(&policy)?;
    validate_bound_head(opening)?;
    if opening.handle.status != CompactSessionStatus::Ready {
        return Err("deterministic drive requires a READY opening handle".to_owned());
    }

    let mut current = opening.clone();
    let mut advances = Vec::new();
    for iteration_index in 0..policy.maximum_tool_calls {
        let transition = apply_compact_coordination_command(
            &current.registry,
            CompactSessionCommand::Advance {
                expected_registry_digest: current.handle.registry_digest.clone(),
                session_id: current.handle.session_id.clone(),
                expected_sequence: current.handle.sequence,
                expected_record_digest: current.handle.record_digest.clone(),
                maximum_steps: policy.maximum_steps_per_call,
            },
        );
        let response = transition.response;
        if response.status != CompactResponseStatus::Succeeded {
            return stopped_after_fault(
                &policy,
                &opening.handle,
                advances,
                current,
                StopReason::CompactFault,
                response,
                None,
            );
        }
        let successor_handle = match response_handle(&response) {
            Ok(handle) => handle.clone(),
            Err(fault) => {
                return stopped_after_fault(
                    &policy,
                    &opening.handle,
                    advances,
                    current,
                    StopReason::CompactFault,
                    response,
                    Some(fault),
                );
            }
        };
        let successor = BoundSession {
            registry: transition.successor,
            handle: successor_handle.clone(),
        };
        if let Err(fault) = validate_bound_head(&successor) {
            return stopped_after_fault(
                &policy,
                &opening.handle,
                advances,
                current,
                StopReason::CompactFault,
                response,
                Some(fault),
            );
        }
        if successor_handle.registry_id != opening.handle.registry_id
            || successor_handle.session_id != opening.handle.session_id
            || successor_handle.sequence
                != current
                    .handle
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| "deterministic drive sequence overflow".to_owned())?
        {
            return stopped_after_fault(
                &policy,
                &opening.handle,
                advances,
                current,
                StopReason::CompactFault,
                response,
                Some("compact successor left the admitted identity or sequence".to_owned()),
            );
        }

        let predecessor_handle = current.handle.clone();
        match successor_handle.status {
            CompactSessionStatus::Ready => {
                let projection = match project_ready_record(&successor.registry, &successor.handle)
                {
                    Ok(projection) => projection,
                    Err(fault) => {
                        return stopped_after_fault(
                            &policy,
                            &opening.handle,
                            advances,
                            successor,
                            StopReason::ProjectionFault,
                            response,
                            Some(fault),
                        );
                    }
                };
                advances.push(DeterministicAdvanceRecord {
                    iteration_index,
                    predecessor_handle,
                    maximum_steps: policy.maximum_steps_per_call,
                    compact_response: response,
                    successor: DeterministicAdvanceSuccessor::Ready { projection },
                });
                current = successor;
            }
            CompactSessionStatus::Terminal => {
                advances.push(DeterministicAdvanceRecord {
                    iteration_index,
                    predecessor_handle,
                    maximum_steps: policy.maximum_steps_per_call,
                    compact_response: response,
                    successor: DeterministicAdvanceSuccessor::Terminal {
                        handle: successor.handle.clone(),
                    },
                });
                current = successor;
                let observation = match read_terminal_observation(&current) {
                    Ok(observation) => observation,
                    Err(fault) => {
                        let (response, fault) = *fault;
                        return stopped_after_fault(
                            &policy,
                            &opening.handle,
                            advances,
                            current,
                            StopReason::ProjectionFault,
                            response,
                            Some(fault),
                        );
                    }
                };
                let result = DeterministicDriveResult {
                    profile: DETERMINISTIC_DRIVE_PROFILE.to_owned(),
                    status: IterativeRunState::Complete,
                    policy,
                    opening_handle: opening.handle.clone(),
                    advances,
                    successor_registry: current.registry,
                    terminal_observation: Some(observation),
                    stopped_head: None,
                    reentry_available: None,
                    stop_reason: None,
                    fault_response: None,
                    fault_message: None,
                    private_reasoning_recorded: false,
                    nonclaims: deterministic_nonclaims(),
                };
                validate_deterministic_drive_result(&result)?;
                return Ok(result);
            }
        }
    }

    let result = DeterministicDriveResult {
        profile: DETERMINISTIC_DRIVE_PROFILE.to_owned(),
        status: IterativeRunState::Stopped,
        policy,
        opening_handle: opening.handle.clone(),
        advances,
        successor_registry: current.registry,
        terminal_observation: None,
        stopped_head: Some(current.handle),
        reentry_available: Some(true),
        stop_reason: Some(StopReason::ToolCallCap),
        fault_response: None,
        fault_message: None,
        private_reasoning_recorded: false,
        nonclaims: deterministic_nonclaims(),
    };
    validate_deterministic_drive_result(&result)?;
    Ok(result)
}

pub fn validate_deterministic_drive_result(
    result: &DeterministicDriveResult,
) -> Result<(), String> {
    if result.profile != DETERMINISTIC_DRIVE_PROFILE {
        return Err("deterministic drive profile is not recognized".to_owned());
    }
    validate_run_policy(&result.policy)?;
    validate_compact_coordination_registry(&result.successor_registry)?;
    if result.private_reasoning_recorded
        || result.nonclaims != deterministic_nonclaims()
        || result.opening_handle.profile != HANDLE_PROFILE
        || result.opening_handle.status != CompactSessionStatus::Ready
        || result.opening_handle.sequence == 0
    {
        return Err("deterministic drive authority or opening identity is invalid".to_owned());
    }

    let mut expected = &result.opening_handle;
    for (index, advance) in result.advances.iter().enumerate() {
        if usize::try_from(advance.iteration_index).ok() != Some(index)
            || &advance.predecessor_handle != expected
            || advance.maximum_steps != result.policy.maximum_steps_per_call
            || advance.compact_response.profile != RESPONSE_PROFILE
            || advance.compact_response.operation != CompactSessionOperation::Advance
            || advance.compact_response.status != CompactResponseStatus::Succeeded
            || advance.compact_response.fault.is_some()
        {
            return Err("deterministic advance identity policy or response is invalid".to_owned());
        }
        let handle = response_handle(&advance.compact_response)?;
        if handle.profile != HANDLE_PROFILE
            || handle.registry_id != result.opening_handle.registry_id
            || handle.session_id != result.opening_handle.session_id
            || handle.sequence
                != advance
                    .predecessor_handle
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| "deterministic advance sequence overflow".to_owned())?
        {
            return Err("deterministic advance leaves identity or sequence continuity".to_owned());
        }
        match &advance.successor {
            DeterministicAdvanceSuccessor::Ready { projection } => {
                if index + 1 == result.advances.len()
                    && result.status == IterativeRunState::Complete
                {
                    return Err("complete deterministic drive ends with READY".to_owned());
                }
                validate_ready_projection(projection, handle)?;
            }
            DeterministicAdvanceSuccessor::Terminal { handle: recorded } => {
                if recorded != handle
                    || handle.status != CompactSessionStatus::Terminal
                    || index + 1 != result.advances.len()
                {
                    return Err(
                        "terminal deterministic successor is misplaced or substituted".to_owned(),
                    );
                }
            }
        }
        expected = handle;
    }

    match result.status {
        IterativeRunState::Complete => validate_complete_drive(result, expected),
        IterativeRunState::Stopped => validate_stopped_drive(result, expected),
    }
}

pub fn normalize_deterministic_drive_result_json(input: &str) -> Result<String, String> {
    let result: DeterministicDriveResult = serde_json::from_str(input)
        .map_err(|error| format!("deterministic drive JSON is invalid: {error}"))?;
    validate_deterministic_drive_result(&result)?;
    serde_json::to_string(&result)
        .map_err(|error| format!("deterministic drive normalization failed: {error}"))
}

pub fn measure_deterministic_drive_result(
    result: &DeterministicDriveResult,
) -> Result<DeterministicDriveMeasurement, String> {
    validate_deterministic_drive_result(result)?;
    let ready_projections = result
        .advances
        .iter()
        .filter_map(|advance| match &advance.successor {
            DeterministicAdvanceSuccessor::Ready { projection } => Some(projection),
            DeterministicAdvanceSuccessor::Terminal { .. } => None,
        })
        .collect::<Vec<_>>();
    let terminal_projection = result
        .terminal_observation
        .as_ref()
        .map(project_terminal_observation)
        .transpose()?;
    let ready_projection_bytes =
        ready_projections
            .iter()
            .try_fold(0_usize, |total, projection| {
                total
                    .checked_add(serialized_bytes(*projection)?)
                    .ok_or_else(|| "READY projection byte count overflow".to_owned())
            })?;
    let terminal_projection_bytes = terminal_projection
        .as_ref()
        .map(serialized_bytes)
        .transpose()?
        .unwrap_or(0);
    let normalized_drive_result_bytes = serialized_bytes(result)?;
    let model_facing_projection_bytes = ready_projection_bytes
        .checked_add(terminal_projection_bytes)
        .ok_or_else(|| "deterministic projection byte count overflow".to_owned())?;
    let measurement = DeterministicDriveMeasurement {
        profile: DETERMINISTIC_DRIVE_MEASUREMENT_PROFILE.to_owned(),
        drive_profile: result.profile.clone(),
        status: result.status,
        maximum_steps_per_call: result.policy.maximum_steps_per_call,
        maximum_tool_calls: result.policy.maximum_tool_calls,
        advance_count: result.advances.len(),
        ready_projection_count: ready_projections.len(),
        opening_handle_bytes: serialized_bytes(&result.opening_handle)?,
        advance_records_bytes: serialized_bytes(&result.advances)?,
        ready_projection_bytes,
        terminal_projection_bytes,
        terminal_observation_bytes: result
            .terminal_observation
            .as_ref()
            .map(serialized_bytes)
            .transpose()?
            .unwrap_or(0),
        successor_registry_bytes: serialized_bytes(&result.successor_registry)?,
        normalized_drive_result_bytes,
        model_facing_projection_bytes,
        model_facing_share_of_result_basis_points: share_basis_points(
            model_facing_projection_bytes,
            normalized_drive_result_bytes,
        )?,
        byte_basis: "compact UTF-8 JSON; projection transport is READY projections plus terminal projection and excludes retained exact registry state".to_owned(),
    };
    validate_deterministic_drive_measurement(&measurement)?;
    Ok(measurement)
}

pub fn validate_deterministic_drive_measurement(
    measurement: &DeterministicDriveMeasurement,
) -> Result<(), String> {
    if measurement.profile != DETERMINISTIC_DRIVE_MEASUREMENT_PROFILE
        || measurement.drive_profile != DETERMINISTIC_DRIVE_PROFILE
        || measurement.advance_count == 0
        || measurement.ready_projection_count > measurement.advance_count
        || measurement.opening_handle_bytes == 0
        || measurement.advance_records_bytes == 0
        || measurement.successor_registry_bytes == 0
        || measurement.normalized_drive_result_bytes == 0
        || measurement.model_facing_projection_bytes
            != measurement
                .ready_projection_bytes
                .checked_add(measurement.terminal_projection_bytes)
                .ok_or_else(|| "measured projection byte count overflow".to_owned())?
        || measurement.model_facing_share_of_result_basis_points
            != share_basis_points(
                measurement.model_facing_projection_bytes,
                measurement.normalized_drive_result_bytes,
            )?
        || measurement.byte_basis
            != "compact UTF-8 JSON; projection transport is READY projections plus terminal projection and excludes retained exact registry state"
    {
        return Err("deterministic drive measurement is inconsistent".to_owned());
    }
    match measurement.status {
        IterativeRunState::Complete => {
            if measurement.terminal_projection_bytes == 0
                || measurement.terminal_observation_bytes == 0
            {
                return Err("complete drive measurement omitted terminal bytes".to_owned());
            }
        }
        IterativeRunState::Stopped => {
            if measurement.terminal_projection_bytes != 0
                || measurement.terminal_observation_bytes != 0
            {
                return Err("stopped drive measurement invented terminal bytes".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_complete_drive(
    result: &DeterministicDriveResult,
    head: &CompactCoordinationHandle,
) -> Result<(), String> {
    let observation = result
        .terminal_observation
        .as_ref()
        .ok_or_else(|| "complete deterministic drive is missing terminal observation".to_owned())?;
    if result.advances.is_empty()
        || head.status != CompactSessionStatus::Terminal
        || result.stopped_head.is_some()
        || result.reentry_available.is_some()
        || result.stop_reason.is_some()
        || result.fault_response.is_some()
        || result.fault_message.is_some()
        || observation.handle != *head
    {
        return Err("complete deterministic drive terminal exclusivity is invalid".to_owned());
    }
    validate_head_in_registry(&result.successor_registry, head)?;
    let projection = project_terminal_observation(observation)?;
    if projection.session_id != head.session_id
        || projection.sequence != head.sequence
        || projection.record_digest != head.record_digest
        || Some(&projection.outcome_digest) != head.outcome_digest.as_ref()
    {
        return Err("terminal observation projection differs from final head".to_owned());
    }
    let exact = read_terminal_observation(&BoundSession {
        registry: result.successor_registry.clone(),
        handle: head.clone(),
    })
    .map_err(|fault| fault.1)?;
    if &exact != observation {
        return Err("terminal observation differs from exact retained READ".to_owned());
    }
    Ok(())
}

fn validate_stopped_drive(
    result: &DeterministicDriveResult,
    expected: &CompactCoordinationHandle,
) -> Result<(), String> {
    let head = result
        .stopped_head
        .as_ref()
        .ok_or_else(|| "stopped deterministic drive is missing its current head".to_owned())?;
    let reason = result
        .stop_reason
        .ok_or_else(|| "stopped deterministic drive is missing its reason".to_owned())?;
    let reentry = result
        .reentry_available
        .ok_or_else(|| "stopped deterministic drive omits reentry availability".to_owned())?;
    if result.terminal_observation.is_some()
        || reentry != (head.status == CompactSessionStatus::Ready)
    {
        return Err("stopped deterministic drive state or reentry claim is invalid".to_owned());
    }
    validate_head_in_registry(&result.successor_registry, head)?;

    match reason {
        StopReason::ToolCallCap => {
            if result.advances.len()
                != usize::try_from(result.policy.maximum_tool_calls)
                    .map_err(|_| "tool-call cap cannot be represented".to_owned())?
                || head != expected
                || head.status != CompactSessionStatus::Ready
                || result.fault_response.is_some()
                || result.fault_message.is_some()
            {
                return Err("tool-call cap did not stop at the exact live READY head".to_owned());
            }
        }
        StopReason::CompactFault | StopReason::ProjectionFault => {
            let response = result
                .fault_response
                .as_ref()
                .ok_or_else(|| "faulted deterministic drive omitted its response".to_owned())?;
            if response.profile != RESPONSE_PROFILE
                || !matches!(
                    response.operation,
                    CompactSessionOperation::Advance | CompactSessionOperation::Read
                )
            {
                return Err("faulted deterministic drive response identity is invalid".to_owned());
            }
            if response.status == CompactResponseStatus::Succeeded
                && result
                    .fault_message
                    .as_deref()
                    .is_none_or(|message| message.trim().is_empty())
            {
                return Err(
                    "successful fault response requires an invariant description".to_owned(),
                );
            }
            if response.status != CompactResponseStatus::Succeeded
                && (response.result.is_some() || response.fault.is_none())
            {
                return Err("failed compact response does not carry an exclusive fault".to_owned());
            }
            match response.operation {
                CompactSessionOperation::Read => {
                    if reason != StopReason::ProjectionFault
                        || head != expected
                        || head.status != CompactSessionStatus::Terminal
                    {
                        return Err(
                            "terminal READ fault does not follow the last terminal head".to_owned()
                        );
                    }
                }
                CompactSessionOperation::Advance => {
                    if response.status == CompactResponseStatus::Succeeded {
                        match response_handle(response) {
                            Ok(attempted) if attempted == head => {
                                if reason != StopReason::ProjectionFault
                                    || attempted.registry_id != result.opening_handle.registry_id
                                    || attempted.session_id != result.opening_handle.session_id
                                    || attempted.sequence
                                        != expected.sequence.checked_add(1).ok_or_else(|| {
                                            "faulted deterministic sequence overflow".to_owned()
                                        })?
                                {
                                    return Err(
                                        "accepted fault response leaves deterministic continuity"
                                            .to_owned(),
                                    );
                                }
                            }
                            _ if head == expected && reason == StopReason::CompactFault => {}
                            _ => {
                                return Err(
                                    "successful fault response is not bound to admitted custody"
                                        .to_owned(),
                                );
                            }
                        }
                    } else if head != expected || reason != StopReason::CompactFault {
                        return Err("refused ADVANCE changed the last admitted head".to_owned());
                    }
                }
                _ => unreachable!("operation was restricted above"),
            }
        }
        _ => {
            return Err("deterministic driver emitted an unsupported stop reason".to_owned());
        }
    }
    Ok(())
}

fn validate_bound_head(bound: &BoundSession) -> Result<(), String> {
    validate_compact_coordination_registry(&bound.registry)?;
    validate_head_in_registry(&bound.registry, &bound.handle)
}

fn validate_head_in_registry(
    registry: &CompactCoordinationRegistry,
    handle: &CompactCoordinationHandle,
) -> Result<(), String> {
    if handle.profile != HANDLE_PROFILE
        || handle.registry_id != registry.registry_id
        || handle.registry_digest != registry.registry_digest
    {
        return Err("compact head does not identify its retained registry".to_owned());
    }
    let record = registry
        .sessions
        .get(&handle.session_id)
        .ok_or_else(|| "compact head session is absent from its retained registry".to_owned())?;
    if handle.session_id != record.session_id
        || handle.sequence != record.sequence
        || handle.record_digest != record.record_digest
    {
        return Err("compact head differs from its retained record".to_owned());
    }
    match handle.status {
        CompactSessionStatus::Ready => {
            let checkpoint = record
                .checkpoint
                .as_ref()
                .ok_or_else(|| "READY head is missing its checkpoint".to_owned())?;
            if record.outcome.is_some()
                || handle.checkpoint_digest.as_ref() != Some(&checkpoint.checkpoint_digest)
                || handle.outcome_digest.is_some()
            {
                return Err("READY head and retained state shape differ".to_owned());
            }
        }
        CompactSessionStatus::Terminal => {
            let _outcome = record
                .outcome
                .as_ref()
                .ok_or_else(|| "terminal head is missing its outcome".to_owned())?;
            if record.checkpoint.is_some()
                || handle.checkpoint_digest.is_some()
                || handle.outcome_digest.is_none()
            {
                return Err("terminal head and retained state shape differ".to_owned());
            }
        }
    }
    let inspection = apply_compact_coordination_command(
        registry,
        CompactSessionCommand::Inspect {
            expected_registry_digest: registry.registry_digest.clone(),
            session_id: handle.session_id.clone(),
        },
    );
    if inspection.successor != *registry
        || inspection.response.status != CompactResponseStatus::Succeeded
        || response_handle(&inspection.response)? != handle
    {
        return Err("compact head differs from a fresh exact inspection".to_owned());
    }
    Ok(())
}

fn stopped_after_fault(
    policy: &RunPolicy,
    opening_handle: &CompactCoordinationHandle,
    advances: Vec<DeterministicAdvanceRecord>,
    current: BoundSession,
    stop_reason: StopReason,
    response: CompactSessionResponse,
    fault_message: Option<String>,
) -> Result<DeterministicDriveResult, String> {
    let result = DeterministicDriveResult {
        profile: DETERMINISTIC_DRIVE_PROFILE.to_owned(),
        status: IterativeRunState::Stopped,
        policy: policy.clone(),
        opening_handle: opening_handle.clone(),
        advances,
        successor_registry: current.registry,
        terminal_observation: None,
        stopped_head: Some(current.handle.clone()),
        reentry_available: Some(current.handle.status == CompactSessionStatus::Ready),
        stop_reason: Some(stop_reason),
        fault_response: Some(response),
        fault_message,
        private_reasoning_recorded: false,
        nonclaims: deterministic_nonclaims(),
    };
    validate_deterministic_drive_result(&result)?;
    Ok(result)
}

fn read_terminal_observation(
    session: &BoundSession,
) -> Result<TerminalObservation, Box<(CompactSessionResponse, String)>> {
    if let Err(fault) = validate_bound_head(session) {
        let response = apply_compact_coordination_command(
            &session.registry,
            CompactSessionCommand::Read {
                expected_registry_digest: session.handle.registry_digest.clone(),
                session_id: session.handle.session_id.clone(),
            },
        )
        .response;
        return Err(Box::new((response, fault)));
    }
    if session.handle.status != CompactSessionStatus::Terminal {
        let response = apply_compact_coordination_command(
            &session.registry,
            CompactSessionCommand::Read {
                expected_registry_digest: session.handle.registry_digest.clone(),
                session_id: session.handle.session_id.clone(),
            },
        )
        .response;
        return Err(Box::new((
            response,
            "terminal READ requires a terminal head".to_owned(),
        )));
    }
    let read = apply_compact_coordination_command(
        &session.registry,
        CompactSessionCommand::Read {
            expected_registry_digest: session.handle.registry_digest.clone(),
            session_id: session.handle.session_id.clone(),
        },
    );
    let response = read.response;
    if read.successor != session.registry {
        return Err(Box::new((
            response,
            "terminal READ unexpectedly changed the retained registry".to_owned(),
        )));
    }
    let (handle, record_json, record_digest) = match response.result.as_ref() {
        Some(CompactSessionResult::Record {
            handle,
            record_json,
            record_digest,
        }) if response.status == CompactResponseStatus::Succeeded => {
            (handle, record_json, record_digest)
        }
        _ => {
            return Err(Box::new((
                response,
                "terminal READ did not return an exact successful record".to_owned(),
            )));
        }
    };
    if handle != &session.handle || record_digest != &session.handle.record_digest {
        return Err(Box::new((
            response,
            "terminal READ identity differs from its exact head".to_owned(),
        )));
    }
    let outcome_digest = session.handle.outcome_digest.clone().ok_or_else(|| {
        (
            response.clone(),
            "terminal head omitted outcome digest".to_owned(),
        )
    })?;
    let observation = TerminalObservation {
        observed_status: "terminal_outcome".to_owned(),
        handle: handle.clone(),
        record_json: record_json.clone(),
        outcome_digest,
    };
    project_terminal_observation(&observation).map_err(|fault| Box::new((response, fault)))?;
    Ok(observation)
}

fn deterministic_nonclaims() -> Vec<String> {
    DETERMINISTIC_DRIVE_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn serialized_bytes(value: &impl Serialize) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("deterministic measurement serialization failed: {error}"))
}

fn share_basis_points(numerator: usize, denominator: usize) -> Result<u64, String> {
    if denominator == 0 || numerator > denominator {
        return Err("deterministic measurement share is outside its basis".to_owned());
    }
    let scaled = (numerator as u128)
        .checked_mul(10_000)
        .ok_or_else(|| "deterministic measurement share overflow".to_owned())?
        / denominator as u128;
    u64::try_from(scaled).map_err(|_| "deterministic measurement share overflow".to_owned())
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
    if report.opening_handle.profile != HANDLE_PROFILE
        || report.opening_handle.status != CompactSessionStatus::Ready
        || report.opening_handle.session_id != report.session_id
        || report.opening_handle.sequence != 1
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
    let mut call_ids = BTreeSet::new();
    for (index, iteration) in report.iterations.iter().enumerate() {
        if usize::try_from(iteration.iteration_index).ok() != Some(index)
            || &iteration.predecessor_handle != expected_predecessor
            || iteration.maximum_steps != report.policy.maximum_steps_per_call
            || iteration.call_id.trim().is_empty()
            || !call_ids.insert(iteration.call_id.as_str())
            || iteration.predecessor_handle.status != CompactSessionStatus::Ready
            || iteration.compact_response.profile != RESPONSE_PROFILE
            || iteration.compact_response.operation != CompactSessionOperation::Advance
            || iteration.compact_response.status != CompactResponseStatus::Succeeded
            || iteration.compact_response.fault.is_some()
        {
            return Err("iterative record identity policy or response is invalid".to_owned());
        }
        let successor_handle = response_handle(&iteration.compact_response)?;
        if successor_handle.profile != HANDLE_PROFILE
            || successor_handle.registry_id != report.opening_handle.registry_id
            || successor_handle.session_id != report.session_id
            || successor_handle.sequence
                != iteration
                    .predecessor_handle
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| "iteration sequence overflow".to_owned())?
        {
            return Err("iteration successor leaves identity or sequence continuity".to_owned());
        }
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
        || report.usage.provider_calls > report.usage.tool_calls.saturating_add(1)
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
    if report.stop_reason == Some(StopReason::ToolCallCap)
        && report.usage.tool_calls != report.policy.maximum_tool_calls
    {
        return Err("tool-call-cap stop occurred before its declared cap".to_owned());
    }
    if report.stop_reason == Some(StopReason::ProviderCallCap)
        && report.usage.provider_calls != report.policy.maximum_provider_calls
    {
        return Err("provider-call-cap stop occurred before its declared cap".to_owned());
    }
    Ok(())
}
