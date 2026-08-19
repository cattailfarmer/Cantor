//! Provider-free READY stopped orchestration and live reentry proof.

use cantor_compact_coordination_mcp::{
    CompactCoordinationRegistry, CompactResponseStatus, CompactSessionCommand,
    CompactSessionResult, CompactSessionStatus, apply_compact_coordination_command,
    validate_compact_coordination_registry,
};
use cantor_core::SemanticId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    BoundSession, ITERATIVE_REPORT_NONCLAIMS, IterationRecord, IterationSuccessor,
    IterativeProviderPhase, IterativeReport, IterativeRunState, PolicyUsage, RunPolicy,
    SCRIPTED_PROVIDER_BASE, StopReason, TOOL_NAME, admit_iterative_provider_iteration,
    drive_bound_session, experimental_fixture_context_json, extract_advance_call,
    iterative_advance_request, open_bound_session, sanitize, validate_iterative_provider_prefix,
    validate_iterative_report, validate_run_policy,
};

pub const SCRIPTED_STOPPED_RUN_PROFILE: &str = "cantor-scripted-iterative-stopped-run/0.1";
pub const SCRIPTED_STOPPED_RUN_NONCLAIMS: [&str; 6] = [
    "stopped state is READY and not complete",
    "scripted response envelopes are fixture evidence not model output",
    "no provider network model or process call was performed",
    "exact live reentry requires the returned registry and handle",
    "no hidden-state or live-token insertion",
    "no external effect semantic-truth or producer-authentication claim",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedStoppedRun {
    pub profile: String,
    pub prompt: String,
    pub report: IterativeReport,
    pub successor_registry: CompactCoordinationRegistry,
    pub failed_request: Option<Value>,
    pub sanitized_failed_response: Option<Value>,
    pub fault_message: Option<String>,
    pub provider_execution_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn run_scripted_ready_stopped(
    opening: &BoundSession,
    model: &str,
    prompt: &str,
    policy: RunPolicy,
    scripted_responses: &[Value],
) -> Result<ScriptedStoppedRun, String> {
    validate_run_policy(&policy)?;
    let mut current = opening.clone();
    let mut iterations = Vec::<IterationRecord>::new();
    let mut provider_calls = 0_u32;
    let mut response_index = 0_usize;

    loop {
        if iterations.len()
            == usize::try_from(policy.maximum_tool_calls)
                .map_err(|_| "scripted tool-call cap cannot be represented".to_owned())?
        {
            if response_index != scripted_responses.len() {
                return Err("scripted responses remain after the tool-call cap".to_owned());
            }
            return stopped_run(
                opening,
                model,
                prompt,
                policy,
                iterations,
                current,
                provider_calls,
                StopReason::ToolCallCap,
                None,
                None,
                None,
            );
        }

        let request =
            iterative_advance_request(model, prompt, &policy, &opening.handle, &iterations)?;
        let Some(raw_response) = scripted_responses.get(response_index) else {
            return stopped_run(
                opening,
                model,
                prompt,
                policy,
                iterations,
                current,
                provider_calls,
                StopReason::ProviderProtocolFault,
                Some(request),
                None,
                Some("scripted provider response is unavailable".to_owned()),
            );
        };
        response_index += 1;
        provider_calls = provider_calls
            .checked_add(1)
            .ok_or_else(|| "scripted provider-call count overflow".to_owned())?;
        let sanitized_response = sanitize(raw_response);
        if let Err(fault) = validate_scripted_response(
            &sanitized_response,
            policy.maximum_steps_per_call,
            &iterations,
        ) {
            if response_index != scripted_responses.len() {
                return Err("scripted responses remain after provider-protocol fault".to_owned());
            }
            return stopped_run(
                opening,
                model,
                prompt,
                policy,
                iterations,
                current,
                provider_calls,
                StopReason::ProviderProtocolFault,
                Some(request),
                Some(sanitized_response),
                Some(fault),
            );
        }

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
            &sanitized_response,
            &one_advance,
        )?;
        if matches!(iteration.successor, IterationSuccessor::Terminal { .. }) {
            return Err(
                "scripted stopped runner reached terminal; use the complete orchestrator"
                    .to_owned(),
            );
        }
        iterations.push(iteration);
        let head = one_advance
            .stopped_head
            .ok_or_else(|| "scripted READY advance omitted its live head".to_owned())?;
        current = BoundSession {
            registry: one_advance.successor_registry,
            handle: head,
        };
    }
}

pub fn generate_scripted_tool_cap_fixture() -> Result<ScriptedStoppedRun, String> {
    let opening = fixture_opening("tool-cap")?;
    run_scripted_ready_stopped(
        &opening,
        "scripted-fixture-model",
        "Stop the provider-free fixture at its READY tool-call cap.",
        RunPolicy {
            maximum_steps_per_call: 8,
            maximum_tool_calls: 1,
            maximum_provider_calls: 2,
            timeout_seconds: 120,
        },
        &[scripted_response("call-scripted-cap", 8)],
    )
}

pub fn generate_scripted_exhaustion_fixture() -> Result<ScriptedStoppedRun, String> {
    let opening = fixture_opening("exhaustion")?;
    run_scripted_ready_stopped(
        &opening,
        "scripted-fixture-model",
        "Stop the provider-free fixture when its response script ends.",
        RunPolicy {
            maximum_steps_per_call: 8,
            maximum_tool_calls: 8,
            maximum_provider_calls: 9,
            timeout_seconds: 120,
        },
        &[scripted_response("call-scripted-before-exhaustion", 8)],
    )
}

pub fn resume_scripted_stopped(run: &ScriptedStoppedRun) -> Result<BoundSession, String> {
    validate_scripted_stopped_run(run)?;
    let handle = run
        .report
        .reentry_handle
        .clone()
        .ok_or_else(|| "scripted stopped run omitted reentry handle".to_owned())?;
    Ok(BoundSession {
        registry: run.successor_registry.clone(),
        handle,
    })
}

pub fn validate_scripted_stopped_run(run: &ScriptedStoppedRun) -> Result<(), String> {
    if run.profile != SCRIPTED_STOPPED_RUN_PROFILE
        || run.provider_execution_claimed
        || run.nonclaims != stopped_nonclaims()
        || run.report.base_url != SCRIPTED_PROVIDER_BASE
        || run.report.status != IterativeRunState::Stopped
        || run.report.usage.elapsed_milliseconds != 0
        || run.report.reentry_available != Some(true)
    {
        return Err("scripted stopped run identity or nonclaim boundary is invalid".to_owned());
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
    let reentry = run
        .report
        .reentry_handle
        .as_ref()
        .ok_or_else(|| "scripted stopped run omitted its reentry handle".to_owned())?;
    if prefix.phase != IterativeProviderPhase::Advance
        || &prefix.head_handle != reentry
        || reentry.status != CompactSessionStatus::Ready
        || run.report.usage.tool_calls as usize != run.report.iterations.len()
    {
        return Err("scripted stopped run prefix usage or READY head is invalid".to_owned());
    }
    validate_ready_registry(&run.successor_registry, reentry)?;

    match run.report.stop_reason {
        Some(StopReason::ToolCallCap) => {
            if run.failed_request.is_some()
                || run.sanitized_failed_response.is_some()
                || run.fault_message.is_some()
                || run.report.usage.provider_calls != run.report.usage.tool_calls
            {
                return Err(
                    "scripted tool-cap stop carries contradictory fault evidence".to_owned(),
                );
            }
        }
        Some(StopReason::ProviderProtocolFault) => {
            let expected_request = iterative_advance_request(
                &run.report.model,
                &run.prompt,
                &run.report.policy,
                &run.report.opening_handle,
                &run.report.iterations,
            )?;
            if run.failed_request.as_ref() != Some(&expected_request)
                || run
                    .fault_message
                    .as_deref()
                    .is_none_or(|message| message.trim().is_empty())
            {
                return Err(
                    "scripted protocol stop omitted its failed request or reason".to_owned(),
                );
            }
            match run.sanitized_failed_response.as_ref() {
                Some(response) => {
                    if response != &sanitize(response)
                        || run.report.usage.provider_calls
                            != run.report.usage.tool_calls.saturating_add(1)
                        || validate_scripted_response(
                            response,
                            run.report.policy.maximum_steps_per_call,
                            &run.report.iterations,
                        )
                        .is_ok()
                    {
                        return Err("scripted invalid response evidence is inconsistent".to_owned());
                    }
                }
                None => {
                    if run.report.usage.provider_calls != run.report.usage.tool_calls {
                        return Err("missing scripted response was counted as supplied".to_owned());
                    }
                }
            }
        }
        _ => return Err("scripted stopped run uses an unsupported stop reason".to_owned()),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn stopped_run(
    opening: &BoundSession,
    model: &str,
    prompt: &str,
    policy: RunPolicy,
    iterations: Vec<IterationRecord>,
    current: BoundSession,
    provider_calls: u32,
    stop_reason: StopReason,
    failed_request: Option<Value>,
    sanitized_failed_response: Option<Value>,
    fault_message: Option<String>,
) -> Result<ScriptedStoppedRun, String> {
    let tool_calls = u32::try_from(iterations.len())
        .map_err(|_| "scripted tool-call count cannot be represented".to_owned())?;
    let report = IterativeReport {
        profile: crate::ITERATIVE_REPORT_PROFILE.to_owned(),
        status: IterativeRunState::Stopped,
        policy,
        usage: PolicyUsage {
            tool_calls,
            provider_calls,
            elapsed_milliseconds: 0,
        },
        base_url: SCRIPTED_PROVIDER_BASE.to_owned(),
        model: model.to_owned(),
        session_id: opening.handle.session_id.clone(),
        opening_handle: opening.handle.clone(),
        iterations,
        terminal_observation: None,
        terminal_projection: None,
        final_output: None,
        reentry_handle: Some(current.handle),
        reentry_available: Some(true),
        stop_reason: Some(stop_reason),
        private_reasoning_recorded: false,
        nonclaims: ITERATIVE_REPORT_NONCLAIMS
            .iter()
            .map(ToString::to_string)
            .collect(),
    };
    let run = ScriptedStoppedRun {
        profile: SCRIPTED_STOPPED_RUN_PROFILE.to_owned(),
        prompt: prompt.to_owned(),
        report,
        successor_registry: current.registry,
        failed_request,
        sanitized_failed_response,
        fault_message,
        provider_execution_claimed: false,
        nonclaims: stopped_nonclaims(),
    };
    validate_scripted_stopped_run(&run)?;
    Ok(run)
}

fn validate_scripted_response(
    response: &Value,
    maximum_steps: u64,
    iterations: &[IterationRecord],
) -> Result<(), String> {
    let call = extract_advance_call(response, maximum_steps)?;
    if call.call_id.trim().is_empty()
        || call.call_id.len() > 1_024
        || call
            .assistant_message
            .pointer("/tool_calls/0/type")
            .and_then(Value::as_str)
            != Some("function")
        || iterations
            .iter()
            .any(|iteration| iteration.call_id == call.call_id)
    {
        return Err("scripted provider call identity or type is invalid".to_owned());
    }
    Ok(())
}

fn validate_ready_registry(
    registry: &CompactCoordinationRegistry,
    head: &cantor_compact_coordination_mcp::CompactCoordinationHandle,
) -> Result<(), String> {
    let inspect = apply_compact_coordination_command(
        registry,
        CompactSessionCommand::Inspect {
            expected_registry_digest: registry.registry_digest.clone(),
            session_id: head.session_id.clone(),
        },
    );
    match inspect.response.result.as_ref() {
        Some(CompactSessionResult::State { handle })
            if inspect.response.status == CompactResponseStatus::Succeeded
                && inspect.successor == *registry
                && handle == head
                && handle.status == CompactSessionStatus::Ready =>
        {
            Ok(())
        }
        _ => Err("scripted stopped registry INSPECT differs from READY reentry".to_owned()),
    }
}

fn fixture_opening(label: &str) -> Result<BoundSession, String> {
    open_bound_session(
        experimental_fixture_context_json()?,
        SemanticId::new(format!("registry:scripted-stopped-{label}"))
            .map_err(|fault| fault.to_string())?,
        SemanticId::new(format!("session:scripted-stopped-{label}"))
            .map_err(|fault| fault.to_string())?,
    )
}

fn scripted_response(call_id: &str, maximum_steps: u64) -> Value {
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

fn stopped_nonclaims() -> Vec<String> {
    SCRIPTED_STOPPED_RUN_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
