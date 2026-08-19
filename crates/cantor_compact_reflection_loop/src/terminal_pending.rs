//! Provider-free terminal-reflection-pending orchestration and admission.

use std::collections::BTreeSet;

use cantor_compact_coordination_mcp::{
    CompactCoordinationHandle, CompactCoordinationRegistry, validate_compact_coordination_registry,
};
use cantor_core::SemanticId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    BoundSession, FINAL_STATEMENT, FinalOutput, ITERATIVE_REPORT_NONCLAIMS, IterationRecord,
    IterationSuccessor, IterativeProviderPhase, IterativeReport, IterativeRunState, PolicyUsage,
    RunPolicy, SCRIPTED_COMPLETE_RUN_NONCLAIMS, SCRIPTED_COMPLETE_RUN_PROFILE,
    SCRIPTED_PROVIDER_BASE, ScriptedCompleteRun, TerminalObservation, TerminalProjection,
    admit_iterative_provider_iteration, drive_bound_session, experimental_fixture_context_json,
    extract_final_output, iterative_terminal_reflection_request, open_bound_session,
    project_terminal_observation, sanitize, scripted_orchestrator::scripted_advance_response,
    scripted_orchestrator::validate_terminal_registry, validate_iterative_provider_prefix,
    validate_run_policy, validate_scripted_complete_run,
};

pub const TERMINAL_PENDING_REPORT_PROFILE: &str = "cantor-terminal-reflection-pending-report/0.1";
pub const SCRIPTED_TERMINAL_PENDING_PROFILE: &str =
    "cantor-scripted-terminal-reflection-pending-run/0.1";
pub const TERMINAL_PENDING_REPORT_NONCLAIMS: [&str; 6] = [
    "terminal procedure state is not final semantic reflection",
    "no ADVANCE reentry remains",
    "no terminal reflection response or final output was admitted",
    "no hidden-state or live-token insertion",
    "no external effect or semantic-truth claim",
    "no persistent authenticated remote or OneDrive session",
];
pub const SCRIPTED_TERMINAL_PENDING_NONCLAIMS: [&str; 6] = [
    "scripted advance envelopes are fixture evidence not model output",
    "no provider network model or process call was performed",
    "one terminal reflection response remains pending",
    "exact terminal state remains under host custody",
    "no hidden-state or live-token insertion",
    "no external effect semantic-truth or producer-authentication claim",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalReflectionPendingReport {
    pub profile: String,
    pub policy: RunPolicy,
    pub usage: PolicyUsage,
    pub base_url: String,
    pub model: String,
    pub session_id: SemanticId,
    pub opening_handle: CompactCoordinationHandle,
    pub iterations: Vec<IterationRecord>,
    pub terminal_observation: TerminalObservation,
    pub terminal_projection: TerminalProjection,
    pub private_reasoning_recorded: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedTerminalPendingRun {
    pub profile: String,
    pub prompt: String,
    pub report: TerminalReflectionPendingReport,
    pub successor_registry: CompactCoordinationRegistry,
    pub terminal_reflection_request: Value,
    pub provider_execution_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn run_scripted_terminal_pending(
    opening: &BoundSession,
    model: &str,
    prompt: &str,
    policy: RunPolicy,
    call_ids: &[String],
) -> Result<ScriptedTerminalPendingRun, String> {
    validate_run_policy(&policy)?;
    if call_ids.is_empty() {
        return Err("scripted terminal-pending run requires at least one call identity".to_owned());
    }
    if call_ids.len()
        > usize::try_from(policy.maximum_tool_calls)
            .map_err(|_| "scripted tool-call cap cannot be represented".to_owned())?
    {
        return Err("scripted call identities exceed the tool-call cap".to_owned());
    }
    if call_ids.iter().collect::<BTreeSet<_>>().len() != call_ids.len() {
        return Err("scripted call identities are not unique".to_owned());
    }

    let mut current = opening.clone();
    let mut iterations = Vec::<IterationRecord>::new();
    for (index, call_id) in call_ids.iter().enumerate() {
        let response = scripted_advance_response(call_id, policy.maximum_steps_per_call);
        let one_advance = drive_bound_session(
            &current,
            RunPolicy {
                maximum_steps_per_call: policy.maximum_steps_per_call,
                maximum_tool_calls: 1,
                maximum_provider_calls: 2,
                timeout_seconds: policy.timeout_seconds,
            },
        )?;
        let iteration = admit_iterative_provider_iteration(
            model,
            prompt,
            &policy,
            &opening.handle,
            &iterations,
            &response,
            &one_advance,
        )?;
        let terminal = matches!(iteration.successor, IterationSuccessor::Terminal { .. });
        iterations.push(iteration);
        if terminal {
            if index + 1 != call_ids.len() {
                return Err("scripted call identities remain after terminal".to_owned());
            }
            return build_terminal_pending(opening, model, prompt, policy, iterations, one_advance);
        }
        let head = one_advance
            .stopped_head
            .ok_or_else(|| "scripted READY advance omitted its live head".to_owned())?;
        current = BoundSession {
            registry: one_advance.successor_registry,
            handle: head,
        };
    }
    Err("scripted call identities ended before terminal state".to_owned())
}

pub fn generate_scripted_terminal_pending_fixture() -> Result<ScriptedTerminalPendingRun, String> {
    let opening = open_bound_session(
        experimental_fixture_context_json()?,
        SemanticId::new("registry:scripted-terminal-pending").map_err(|fault| fault.to_string())?,
        SemanticId::new("session:scripted-terminal-pending").map_err(|fault| fault.to_string())?,
    )?;
    run_scripted_terminal_pending(
        &opening,
        "scripted-fixture-model",
        "Reach terminal state and wait for provider-free scripted reflection.",
        RunPolicy {
            maximum_steps_per_call: 8,
            maximum_tool_calls: 8,
            maximum_provider_calls: 9,
            timeout_seconds: 120,
        },
        &[
            "call-scripted-pending-0".to_owned(),
            "call-scripted-pending-1".to_owned(),
        ],
    )
}

pub fn admit_scripted_terminal_reflection(
    pending: &ScriptedTerminalPendingRun,
    raw_response: &Value,
) -> Result<ScriptedCompleteRun, String> {
    validate_scripted_terminal_pending_run(pending)?;
    let sanitized_response = sanitize(raw_response);
    let final_output =
        extract_final_output(&sanitized_response, &pending.report.terminal_projection)?;
    let provider_calls = pending
        .report
        .usage
        .provider_calls
        .checked_add(1)
        .ok_or_else(|| "scripted provider-call count overflow".to_owned())?;
    if provider_calls > pending.report.policy.maximum_provider_calls {
        return Err("terminal reflection exceeds the provider-call cap".to_owned());
    }
    let report = IterativeReport {
        profile: crate::ITERATIVE_REPORT_PROFILE.to_owned(),
        status: IterativeRunState::Complete,
        policy: pending.report.policy.clone(),
        usage: PolicyUsage {
            tool_calls: pending.report.usage.tool_calls,
            provider_calls,
            elapsed_milliseconds: pending.report.usage.elapsed_milliseconds,
        },
        base_url: pending.report.base_url.clone(),
        model: pending.report.model.clone(),
        session_id: pending.report.session_id.clone(),
        opening_handle: pending.report.opening_handle.clone(),
        iterations: pending.report.iterations.clone(),
        terminal_observation: Some(pending.report.terminal_observation.clone()),
        terminal_projection: Some(pending.report.terminal_projection.clone()),
        final_output: Some(final_output),
        reentry_handle: None,
        reentry_available: None,
        stop_reason: None,
        private_reasoning_recorded: false,
        nonclaims: ITERATIVE_REPORT_NONCLAIMS
            .iter()
            .map(ToString::to_string)
            .collect(),
    };
    let complete = ScriptedCompleteRun {
        profile: SCRIPTED_COMPLETE_RUN_PROFILE.to_owned(),
        prompt: pending.prompt.clone(),
        report,
        successor_registry: pending.successor_registry.clone(),
        terminal_reflection_request: pending.terminal_reflection_request.clone(),
        sanitized_terminal_reflection_response: sanitized_response,
        provider_execution_claimed: false,
        nonclaims: SCRIPTED_COMPLETE_RUN_NONCLAIMS
            .iter()
            .map(ToString::to_string)
            .collect(),
    };
    validate_scripted_complete_run(&complete)?;
    Ok(complete)
}

pub fn validate_terminal_reflection_pending_report(
    report: &TerminalReflectionPendingReport,
    prompt: &str,
) -> Result<(), String> {
    if report.profile != TERMINAL_PENDING_REPORT_PROFILE
        || report.private_reasoning_recorded
        || report.nonclaims != pending_report_nonclaims()
        || report.base_url != SCRIPTED_PROVIDER_BASE
        || report.session_id != report.opening_handle.session_id
        || report.usage.elapsed_milliseconds != 0
        || report.usage.tool_calls as usize != report.iterations.len()
        || report.usage.provider_calls != report.usage.tool_calls
        || report.usage.tool_calls > report.policy.maximum_tool_calls
        || report.usage.provider_calls > report.policy.maximum_provider_calls
    {
        return Err("terminal-pending report identity usage or nonclaim is invalid".to_owned());
    }
    let prefix = validate_iterative_provider_prefix(
        &report.model,
        prompt,
        &report.policy,
        &report.opening_handle,
        &report.iterations,
    )?;
    if prefix.phase != IterativeProviderPhase::ReflectTerminal
        || prefix.head_handle != report.terminal_observation.handle
        || project_terminal_observation(&report.terminal_observation)? != report.terminal_projection
    {
        return Err("terminal-pending prefix observation or projection is invalid".to_owned());
    }
    Ok(())
}

pub fn validate_scripted_terminal_pending_run(
    run: &ScriptedTerminalPendingRun,
) -> Result<(), String> {
    if run.profile != SCRIPTED_TERMINAL_PENDING_PROFILE
        || run.provider_execution_claimed
        || run.nonclaims != scripted_pending_nonclaims()
    {
        return Err("scripted terminal-pending identity or nonclaim is invalid".to_owned());
    }
    validate_terminal_reflection_pending_report(&run.report, &run.prompt)?;
    validate_compact_coordination_registry(&run.successor_registry)?;
    validate_terminal_registry(&run.successor_registry, &run.report.terminal_observation)?;
    let expected_request = iterative_terminal_reflection_request(
        &run.report.model,
        &run.prompt,
        &run.report.policy,
        &run.report.opening_handle,
        &run.report.iterations,
    )?;
    if run.terminal_reflection_request != expected_request
        || run.terminal_reflection_request["tool_choice"] != json!("none")
    {
        return Err("scripted terminal-pending reflection request differs from replay".to_owned());
    }
    Ok(())
}

fn build_terminal_pending(
    opening: &BoundSession,
    model: &str,
    prompt: &str,
    policy: RunPolicy,
    iterations: Vec<IterationRecord>,
    terminal_drive: crate::DeterministicDriveResult,
) -> Result<ScriptedTerminalPendingRun, String> {
    let terminal_observation = terminal_drive
        .terminal_observation
        .ok_or_else(|| "scripted terminal advance omitted observation".to_owned())?;
    let terminal_projection = project_terminal_observation(&terminal_observation)?;
    let terminal_reflection_request = iterative_terminal_reflection_request(
        model,
        prompt,
        &policy,
        &opening.handle,
        &iterations,
    )?;
    let tool_calls = u32::try_from(iterations.len())
        .map_err(|_| "scripted tool-call count cannot be represented".to_owned())?;
    let report = TerminalReflectionPendingReport {
        profile: TERMINAL_PENDING_REPORT_PROFILE.to_owned(),
        policy,
        usage: PolicyUsage {
            tool_calls,
            provider_calls: tool_calls,
            elapsed_milliseconds: 0,
        },
        base_url: SCRIPTED_PROVIDER_BASE.to_owned(),
        model: model.to_owned(),
        session_id: opening.handle.session_id.clone(),
        opening_handle: opening.handle.clone(),
        iterations,
        terminal_observation,
        terminal_projection,
        private_reasoning_recorded: false,
        nonclaims: pending_report_nonclaims(),
    };
    let run = ScriptedTerminalPendingRun {
        profile: SCRIPTED_TERMINAL_PENDING_PROFILE.to_owned(),
        prompt: prompt.to_owned(),
        report,
        successor_registry: terminal_drive.successor_registry,
        terminal_reflection_request,
        provider_execution_claimed: false,
        nonclaims: scripted_pending_nonclaims(),
    };
    validate_scripted_terminal_pending_run(&run)?;
    Ok(run)
}

fn pending_report_nonclaims() -> Vec<String> {
    TERMINAL_PENDING_REPORT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn scripted_pending_nonclaims() -> Vec<String> {
    SCRIPTED_TERMINAL_PENDING_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

pub fn scripted_terminal_reflection_response(projection: &TerminalProjection) -> Value {
    let output = FinalOutput {
        observed_status: projection.observed_status.clone(),
        session_id: projection.session_id.clone(),
        outcome_digest: projection.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    json!({
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": serde_json::to_string(&output)
                    .expect("fixture final output always serializes")
            }
        }]
    })
}
