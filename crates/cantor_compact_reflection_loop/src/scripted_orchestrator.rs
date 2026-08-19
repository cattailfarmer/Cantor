//! Provider-free scripted orchestration proof for the complete iterative path.

use std::collections::BTreeSet;

use cantor_compact_coordination_mcp::{
    CompactCoordinationRegistry, CompactResponseStatus, CompactSessionCommand,
    CompactSessionResult, CompactSessionStatus, apply_compact_coordination_command,
    validate_compact_coordination_registry,
};
use cantor_core::SemanticId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    BoundSession, FINAL_STATEMENT, FinalOutput, ITERATIVE_REPORT_NONCLAIMS, IterationRecord,
    IterationSuccessor, IterativeReport, IterativeRunState, PolicyUsage, RunPolicy, TOOL_NAME,
    drive_bound_session, experimental_fixture_context_json, extract_final_output,
    iterative_terminal_reflection_request, open_bound_session, project_terminal_observation,
    sanitize, validate_iterative_provider_prefix, validate_iterative_report, validate_run_policy,
};

pub const SCRIPTED_COMPLETE_RUN_PROFILE: &str = "cantor-scripted-iterative-complete-run/0.1";
pub const SCRIPTED_PROVIDER_BASE: &str = "in-memory://cantor-scripted-provider";
pub const SCRIPTED_COMPLETE_RUN_NONCLAIMS: [&str; 6] = [
    "provider response envelopes were synthesized fixtures not model output",
    "no provider network model or process call was performed",
    "only the complete path is represented",
    "exact procedure state remains under host custody",
    "no hidden-state or live-token insertion",
    "no external effect semantic-truth or producer-authentication claim",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedCompleteRun {
    pub profile: String,
    pub prompt: String,
    pub report: IterativeReport,
    pub successor_registry: CompactCoordinationRegistry,
    pub terminal_reflection_request: Value,
    pub sanitized_terminal_reflection_response: Value,
    pub provider_execution_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn run_scripted_complete_iterative(
    opening: &BoundSession,
    model: &str,
    prompt: &str,
    policy: RunPolicy,
    call_ids: &[String],
) -> Result<ScriptedCompleteRun, String> {
    validate_run_policy(&policy)?;
    if call_ids.is_empty() {
        return Err("scripted complete run requires at least one call identity".to_owned());
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
        let iteration = crate::admit_iterative_provider_iteration(
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
                return Err("scripted run supplied call identities after terminal".to_owned());
            }
            return complete_scripted_run(opening, model, prompt, policy, iterations, one_advance);
        }
        let head = one_advance
            .stopped_head
            .clone()
            .ok_or_else(|| "scripted READY advance omitted its live head".to_owned())?;
        current = BoundSession {
            registry: one_advance.successor_registry,
            handle: head,
        };
    }
    Err("scripted call identities ended before terminal state".to_owned())
}

pub fn generate_scripted_complete_fixture() -> Result<ScriptedCompleteRun, String> {
    let opening = open_bound_session(
        experimental_fixture_context_json()?,
        SemanticId::new("registry:scripted-iterative-complete")
            .map_err(|fault| fault.to_string())?,
        SemanticId::new("session:scripted-iterative-complete")
            .map_err(|fault| fault.to_string())?,
    )?;
    run_scripted_complete_iterative(
        &opening,
        "scripted-fixture-model",
        "Run the provider-free scripted iterative fixture.",
        RunPolicy {
            maximum_steps_per_call: 8,
            maximum_tool_calls: 8,
            maximum_provider_calls: 9,
            timeout_seconds: 120,
        },
        &["call-scripted-0".to_owned(), "call-scripted-1".to_owned()],
    )
}

pub fn validate_scripted_complete_run(run: &ScriptedCompleteRun) -> Result<(), String> {
    if run.profile != SCRIPTED_COMPLETE_RUN_PROFILE
        || run.provider_execution_claimed
        || run.nonclaims != scripted_nonclaims()
        || run.report.base_url != SCRIPTED_PROVIDER_BASE
        || run.report.status != IterativeRunState::Complete
        || run.report.usage.elapsed_milliseconds != 0
    {
        return Err("scripted complete run identity or nonclaim boundary is invalid".to_owned());
    }
    validate_iterative_report(&run.report)?;
    validate_compact_coordination_registry(&run.successor_registry)?;
    let prefix = validate_iterative_provider_prefix(
        &run.report.model,
        &run.prompt,
        &run.report.policy,
        &run.report.opening_handle,
        &run.report.iterations,
    )?;
    if prefix.phase != crate::IterativeProviderPhase::ReflectTerminal
        || run.report.usage.tool_calls as usize != run.report.iterations.len()
        || run.report.usage.provider_calls != run.report.usage.tool_calls.saturating_add(1)
    {
        return Err("scripted complete run prefix or usage is invalid".to_owned());
    }
    let observation = run
        .report
        .terminal_observation
        .as_ref()
        .ok_or_else(|| "scripted complete run omitted terminal observation".to_owned())?;
    let projection = run
        .report
        .terminal_projection
        .as_ref()
        .ok_or_else(|| "scripted complete run omitted terminal projection".to_owned())?;
    if prefix.head_handle != observation.handle
        || project_terminal_observation(observation)? != *projection
    {
        return Err("scripted complete run terminal prefix and observation differ".to_owned());
    }
    validate_terminal_registry(&run.successor_registry, observation)?;

    let expected_reflection = iterative_terminal_reflection_request(
        &run.report.model,
        &run.prompt,
        &run.report.policy,
        &run.report.opening_handle,
        &run.report.iterations,
    )?;
    if run.terminal_reflection_request != expected_reflection
        || run.sanitized_terminal_reflection_response
            != sanitize(&run.sanitized_terminal_reflection_response)
    {
        return Err("scripted terminal reflection evidence differs from replay".to_owned());
    }
    let final_output =
        extract_final_output(&run.sanitized_terminal_reflection_response, projection)?;
    if run.report.final_output.as_ref() != Some(&final_output) {
        return Err("scripted final output differs from admitted reflection".to_owned());
    }
    Ok(())
}

fn complete_scripted_run(
    opening: &BoundSession,
    model: &str,
    prompt: &str,
    policy: RunPolicy,
    iterations: Vec<IterationRecord>,
    terminal_drive: crate::DeterministicDriveResult,
) -> Result<ScriptedCompleteRun, String> {
    let observation = terminal_drive
        .terminal_observation
        .clone()
        .ok_or_else(|| "scripted terminal advance omitted observation".to_owned())?;
    let projection = project_terminal_observation(&observation)?;
    let reflection_request = iterative_terminal_reflection_request(
        model,
        prompt,
        &policy,
        &opening.handle,
        &iterations,
    )?;
    let expected_output = FinalOutput {
        observed_status: projection.observed_status.clone(),
        session_id: projection.session_id.clone(),
        outcome_digest: projection.outcome_digest.clone(),
        statement: FINAL_STATEMENT.to_owned(),
    };
    let reflection_response = json!({
        "choices": [{
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": serde_json::to_string(&expected_output)
                    .expect("scripted final output always serializes")
            }
        }]
    });
    let sanitized_reflection_response = sanitize(&reflection_response);
    let final_output = extract_final_output(&sanitized_reflection_response, &projection)?;
    let tool_calls = u32::try_from(iterations.len())
        .map_err(|_| "scripted tool-call count cannot be represented".to_owned())?;
    let report = IterativeReport {
        profile: crate::ITERATIVE_REPORT_PROFILE.to_owned(),
        status: IterativeRunState::Complete,
        policy,
        usage: PolicyUsage {
            tool_calls,
            provider_calls: tool_calls
                .checked_add(1)
                .ok_or_else(|| "scripted provider-call count overflow".to_owned())?,
            elapsed_milliseconds: 0,
        },
        base_url: SCRIPTED_PROVIDER_BASE.to_owned(),
        model: model.to_owned(),
        session_id: opening.handle.session_id.clone(),
        opening_handle: opening.handle.clone(),
        iterations,
        terminal_observation: Some(observation),
        terminal_projection: Some(projection),
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
    let run = ScriptedCompleteRun {
        profile: SCRIPTED_COMPLETE_RUN_PROFILE.to_owned(),
        prompt: prompt.to_owned(),
        report,
        successor_registry: terminal_drive.successor_registry,
        terminal_reflection_request: reflection_request,
        sanitized_terminal_reflection_response: sanitized_reflection_response,
        provider_execution_claimed: false,
        nonclaims: scripted_nonclaims(),
    };
    validate_scripted_complete_run(&run)?;
    Ok(run)
}

pub(crate) fn validate_terminal_registry(
    registry: &CompactCoordinationRegistry,
    observation: &crate::TerminalObservation,
) -> Result<(), String> {
    let inspect = apply_compact_coordination_command(
        registry,
        CompactSessionCommand::Inspect {
            expected_registry_digest: registry.registry_digest.clone(),
            session_id: observation.handle.session_id.clone(),
        },
    );
    let inspected_handle = match inspect.response.result.as_ref() {
        Some(CompactSessionResult::State { handle })
            if inspect.response.status == CompactResponseStatus::Succeeded =>
        {
            handle
        }
        _ => return Err("scripted final registry INSPECT failed".to_owned()),
    };
    if inspect.successor != *registry || inspected_handle != &observation.handle {
        return Err("scripted final registry INSPECT differs from observation".to_owned());
    }
    let read = apply_compact_coordination_command(
        registry,
        CompactSessionCommand::Read {
            expected_registry_digest: registry.registry_digest.clone(),
            session_id: observation.handle.session_id.clone(),
        },
    );
    match read.response.result.as_ref() {
        Some(CompactSessionResult::Record {
            handle,
            record_json,
            record_digest,
        }) if read.response.status == CompactResponseStatus::Succeeded
            && read.successor == *registry
            && handle == &observation.handle
            && record_json == &observation.record_json
            && record_digest == &observation.handle.record_digest
            && handle.status == CompactSessionStatus::Terminal =>
        {
            Ok(())
        }
        _ => Err("scripted final registry READ differs from observation".to_owned()),
    }
}

pub(crate) fn scripted_advance_response(call_id: &str, maximum_steps: u64) -> Value {
    json!({
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": TOOL_NAME,
                        "arguments": serde_json::to_string(&json!({
                            "maximum_steps": maximum_steps
                        })).expect("scripted arguments always serialize")
                    }
                }]
            }
        }]
    })
}

fn scripted_nonclaims() -> Vec<String> {
    SCRIPTED_COMPLETE_RUN_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
