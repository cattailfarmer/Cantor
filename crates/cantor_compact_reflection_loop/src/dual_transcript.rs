//! Provider-free dual view of actual compact transport and canonical full replay.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AttentionReentryFrame, IterationRecord, ScriptedCompleteRun, compact_iterative_advance_request,
    compact_terminal_reflection_request, compile_attention_reentry_frame,
    generate_scripted_complete_fixture, validate_compact_attention_request,
    validate_scripted_complete_run,
};

pub const SCRIPTED_COMPACT_TRANSPORT_PROFILE: &str =
    "cantor-scripted-compact-transport-projection/0.1";
pub const SCRIPTED_COMPACT_TRANSPORT_NONCLAIMS: [&str; 7] = [
    "projection is not provider execution",
    "actual_request names experimental intended transport",
    "canonical request remains full-prefix replay authority",
    "structural request correspondence is not semantic output equivalence",
    "no provider compatibility or model quality claim",
    "fixture responses are synthesized and not provider output",
    "no hidden-state live-token external-effect persistence or remote operation",
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttentionTransportKind {
    FullPrefix,
    CompactReentry,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttentionTransportRecord {
    pub iteration_index: u32,
    pub transport_kind: AttentionTransportKind,
    pub actual_request: Value,
    pub reentry_frame: Option<AttentionReentryFrame>,
    pub sanitized_response: Value,
    pub canonical_iteration: IterationRecord,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TerminalReflectionTransport {
    pub transport_kind: AttentionTransportKind,
    pub actual_request: Value,
    pub reentry_frame: AttentionReentryFrame,
    pub canonical_request: Value,
    pub sanitized_response: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransportByteAccount {
    pub canonical_request_bytes: usize,
    pub actual_request_bytes: usize,
    pub canonical_minus_actual_bytes: i64,
    pub byte_basis: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedCompactTransportProjection {
    pub profile: String,
    pub canonical_complete: ScriptedCompleteRun,
    pub iteration_transports: Vec<AttentionTransportRecord>,
    pub terminal_reflection_transport: TerminalReflectionTransport,
    pub request_byte_account: TransportByteAccount,
    pub structural_equivalence_only: bool,
    pub provider_execution_claimed: bool,
    pub semantic_equivalence_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn generate_scripted_compact_transport_projection()
-> Result<ScriptedCompactTransportProjection, String> {
    let canonical_complete = generate_scripted_complete_fixture()?;
    project_compact_transport(&canonical_complete)
}

pub fn project_compact_transport(
    canonical_complete: &ScriptedCompleteRun,
) -> Result<ScriptedCompactTransportProjection, String> {
    validate_scripted_complete_run(canonical_complete)?;
    let report = &canonical_complete.report;
    let mut iteration_transports = Vec::with_capacity(report.iterations.len());
    for (index, canonical_iteration) in report.iterations.iter().enumerate() {
        let prior = &report.iterations[..index];
        let (transport_kind, actual_request, reentry_frame) = if index == 0 {
            (
                AttentionTransportKind::FullPrefix,
                canonical_iteration.request.clone(),
                None,
            )
        } else {
            let frame = compile_attention_reentry_frame(
                &report.model,
                &canonical_complete.prompt,
                &report.policy,
                &report.opening_handle,
                prior,
            )?;
            let request = compact_iterative_advance_request(
                &report.model,
                &canonical_complete.prompt,
                &report.policy,
                &report.opening_handle,
                prior,
            )?;
            (AttentionTransportKind::CompactReentry, request, Some(frame))
        };
        iteration_transports.push(AttentionTransportRecord {
            iteration_index: u32::try_from(index)
                .map_err(|_| "transport iteration index cannot be represented".to_owned())?,
            transport_kind,
            actual_request,
            reentry_frame,
            sanitized_response: canonical_iteration.sanitized_response.clone(),
            canonical_iteration: canonical_iteration.clone(),
        });
    }
    let terminal_frame = compile_attention_reentry_frame(
        &report.model,
        &canonical_complete.prompt,
        &report.policy,
        &report.opening_handle,
        &report.iterations,
    )?;
    let actual_terminal_request = compact_terminal_reflection_request(
        &report.model,
        &canonical_complete.prompt,
        &report.policy,
        &report.opening_handle,
        &report.iterations,
    )?;
    let terminal_reflection_transport = TerminalReflectionTransport {
        transport_kind: AttentionTransportKind::CompactReentry,
        actual_request: actual_terminal_request,
        reentry_frame: terminal_frame,
        canonical_request: canonical_complete.terminal_reflection_request.clone(),
        sanitized_response: canonical_complete
            .sanitized_terminal_reflection_response
            .clone(),
    };
    let request_byte_account = byte_account(&iteration_transports, &terminal_reflection_transport)?;
    let projection = ScriptedCompactTransportProjection {
        profile: SCRIPTED_COMPACT_TRANSPORT_PROFILE.to_owned(),
        canonical_complete: canonical_complete.clone(),
        iteration_transports,
        terminal_reflection_transport,
        request_byte_account,
        structural_equivalence_only: true,
        provider_execution_claimed: false,
        semantic_equivalence_claimed: false,
        nonclaims: transport_nonclaims(),
    };
    validate_scripted_compact_transport_projection(&projection)?;
    Ok(projection)
}

pub fn validate_scripted_compact_transport_projection(
    projection: &ScriptedCompactTransportProjection,
) -> Result<(), String> {
    if projection.profile != SCRIPTED_COMPACT_TRANSPORT_PROFILE
        || !projection.structural_equivalence_only
        || projection.provider_execution_claimed
        || projection.semantic_equivalence_claimed
        || projection.nonclaims != transport_nonclaims()
    {
        return Err("compact transport projection identity or claims are invalid".to_owned());
    }
    validate_scripted_complete_run(&projection.canonical_complete)?;
    let report = &projection.canonical_complete.report;
    if projection.iteration_transports.len() != report.iterations.len() {
        return Err("compact transport count differs from canonical iterations".to_owned());
    }
    for (index, transport) in projection.iteration_transports.iter().enumerate() {
        let canonical = &report.iterations[index];
        if usize::try_from(transport.iteration_index).ok() != Some(index)
            || &transport.canonical_iteration != canonical
            || transport.sanitized_response != canonical.sanitized_response
        {
            return Err("compact transport canonical iteration mapping is invalid".to_owned());
        }
        let prior = &report.iterations[..index];
        if index == 0 {
            if transport.transport_kind != AttentionTransportKind::FullPrefix
                || transport.reentry_frame.is_some()
                || transport.actual_request != canonical.request
            {
                return Err("first transport is not the exact full-prefix request".to_owned());
            }
        } else {
            let expected_frame = compile_attention_reentry_frame(
                &report.model,
                &projection.canonical_complete.prompt,
                &report.policy,
                &report.opening_handle,
                prior,
            )?;
            if transport.transport_kind != AttentionTransportKind::CompactReentry
                || transport.reentry_frame.as_ref() != Some(&expected_frame)
            {
                return Err("later transport omitted its exact compact reentry frame".to_owned());
            }
            validate_compact_attention_request(
                &transport.actual_request,
                &report.model,
                &projection.canonical_complete.prompt,
                &report.policy,
                &report.opening_handle,
                prior,
            )?;
        }
    }
    let terminal = &projection.terminal_reflection_transport;
    let expected_terminal_frame = compile_attention_reentry_frame(
        &report.model,
        &projection.canonical_complete.prompt,
        &report.policy,
        &report.opening_handle,
        &report.iterations,
    )?;
    if terminal.transport_kind != AttentionTransportKind::CompactReentry
        || terminal.reentry_frame != expected_terminal_frame
        || terminal.canonical_request != projection.canonical_complete.terminal_reflection_request
        || terminal.sanitized_response
            != projection
                .canonical_complete
                .sanitized_terminal_reflection_response
    {
        return Err("terminal reflection transport mapping is invalid".to_owned());
    }
    validate_compact_attention_request(
        &terminal.actual_request,
        &report.model,
        &projection.canonical_complete.prompt,
        &report.policy,
        &report.opening_handle,
        &report.iterations,
    )?;
    if projection.request_byte_account != byte_account(&projection.iteration_transports, terminal)?
    {
        return Err("compact transport byte account differs from requests".to_owned());
    }
    Ok(())
}

pub fn pretty_scripted_compact_transport_projection_bytes(
    projection: &ScriptedCompactTransportProjection,
) -> Result<Vec<u8>, String> {
    validate_scripted_compact_transport_projection(projection)?;
    let mut bytes = serde_json::to_vec_pretty(projection)
        .map_err(|error| format!("compact transport serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn byte_account(
    iterations: &[AttentionTransportRecord],
    terminal: &TerminalReflectionTransport,
) -> Result<TransportByteAccount, String> {
    let canonical_request_bytes = checked_sum(
        iterations
            .iter()
            .map(|record| compact_json_bytes(&record.canonical_iteration.request))
            .chain(std::iter::once(compact_json_bytes(
                &terminal.canonical_request,
            ))),
    )?;
    let actual_request_bytes = checked_sum(
        iterations
            .iter()
            .map(|record| compact_json_bytes(&record.actual_request))
            .chain(std::iter::once(compact_json_bytes(
                &terminal.actual_request,
            ))),
    )?;
    Ok(TransportByteAccount {
        canonical_request_bytes,
        actual_request_bytes,
        canonical_minus_actual_bytes: signed_difference(
            canonical_request_bytes,
            actual_request_bytes,
        )?,
        byte_basis: "compact UTF-8 JSON request values; canonical_minus_actual is signed canonical full-prefix bytes minus experimental actual transport bytes".to_owned(),
    })
}

fn compact_json_bytes(value: &Value) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("compact transport request serialization failed: {error}"))
}

fn checked_sum(values: impl IntoIterator<Item = Result<usize, String>>) -> Result<usize, String> {
    values.into_iter().try_fold(0_usize, |sum, value| {
        sum.checked_add(value?)
            .ok_or_else(|| "compact transport byte sum overflow".to_owned())
    })
}

fn signed_difference(left: usize, right: usize) -> Result<i64, String> {
    let left = i64::try_from(left)
        .map_err(|_| "compact transport byte count cannot fit i64".to_owned())?;
    let right = i64::try_from(right)
        .map_err(|_| "compact transport byte count cannot fit i64".to_owned())?;
    left.checked_sub(right)
        .ok_or_else(|| "compact transport byte difference overflow".to_owned())
}

fn transport_nonclaims() -> Vec<String> {
    SCRIPTED_COMPACT_TRANSPORT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
