//! Pure dispatch and supplied-response lifecycle over self-digested transport envelopes.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    AttentionTransportEnvelope, AttentionTransportRecord, ScriptedTransportEnvelopeSet,
    TerminalReflectionTransport, generate_scripted_transport_envelope_set,
    validate_attention_transport_envelope, validate_iteration_transport_envelope_against,
    validate_scripted_transport_envelope_set, validate_terminal_transport_envelope_against,
};

pub const EFFECTLESS_DISPATCH_TRACE_PROFILE: &str = "cantor-effectless-dispatch-trace/0.1";
pub const EFFECTLESS_FIXTURE_DISPATCH_PROFILE: &str =
    "cantor-effectless-fixture-dispatch-record/0.1";
pub const SCRIPTED_EFFECTLESS_DISPATCH_RUN_PROFILE: &str =
    "cantor-scripted-effectless-dispatch-run/0.1";
pub const EFFECTLESS_DISPATCH_NONCLAIMS: [&str; 6] = [
    "fixture dispatch state is not physical provider dispatch",
    "supplied response is not provider provenance",
    "canonical admission is not semantic truth or output equivalence",
    "content digest is not producer authentication",
    "trace is immutable value evidence and not persistence",
    "no model process network stream hidden state live token or external effect",
];
pub const SCRIPTED_EFFECTLESS_DISPATCH_RUN_NONCLAIMS: [&str; 5] = [
    "all dispatch and response values are deterministic fixture data",
    "run does not establish provider compatibility",
    "admission proves exact fixture correspondence only",
    "no provider execution authentication or semantic-equivalence claim",
    "no process network persistence remote hidden-state or external-effect operation",
];

const ENVELOPE_DIGEST_DOMAIN: &str = "cantor.effectless-dispatch.envelope.v1";
const RESPONSE_DIGEST_DOMAIN: &str = "cantor.effectless-dispatch.response.v1";
const FIXTURE_ROUTE: &str = "fixture://cantor-scripted-effectless-dispatch";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectlessDispatchPhase {
    Prepared,
    FixtureDispatchRecorded,
    FixtureResponseRecorded,
    Admitted,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectlessFixtureDispatchRecord {
    pub profile: String,
    pub fixture_route: String,
    pub envelope_digest: ContentDigest,
    pub provider_execution_claimed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectlessDispatchTrace {
    pub profile: String,
    pub envelope: AttentionTransportEnvelope,
    pub envelope_digest: ContentDigest,
    pub phase: EffectlessDispatchPhase,
    pub transition_sequence: u8,
    pub fixture_dispatch: Option<EffectlessFixtureDispatchRecord>,
    pub supplied_response: Option<Value>,
    pub response_digest: Option<ContentDigest>,
    pub canonical_admission_recorded: bool,
    pub provider_execution_claimed: bool,
    pub external_effect_claimed: bool,
    pub persistence_claimed: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedEffectlessDispatchRun {
    pub profile: String,
    pub source_envelopes: ScriptedTransportEnvelopeSet,
    pub iteration_traces: Vec<EffectlessDispatchTrace>,
    pub terminal_reflection_trace: EffectlessDispatchTrace,
    pub admitted_trace_count: usize,
    pub all_admitted: bool,
    pub provider_execution_claimed: bool,
    pub external_effect_claimed: bool,
    pub semantic_equivalence_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn prepare_effectless_dispatch(
    envelope: &AttentionTransportEnvelope,
) -> Result<EffectlessDispatchTrace, String> {
    validate_attention_transport_envelope(envelope)?;
    let trace = EffectlessDispatchTrace {
        profile: EFFECTLESS_DISPATCH_TRACE_PROFILE.to_owned(),
        envelope: envelope.clone(),
        envelope_digest: digest_json(ENVELOPE_DIGEST_DOMAIN, envelope)?,
        phase: EffectlessDispatchPhase::Prepared,
        transition_sequence: 0,
        fixture_dispatch: None,
        supplied_response: None,
        response_digest: None,
        canonical_admission_recorded: false,
        provider_execution_claimed: false,
        external_effect_claimed: false,
        persistence_claimed: false,
        nonclaims: trace_nonclaims(),
    };
    validate_effectless_dispatch_trace(&trace)?;
    Ok(trace)
}

pub fn record_effectless_fixture_dispatch(
    trace: &EffectlessDispatchTrace,
) -> Result<EffectlessDispatchTrace, String> {
    validate_effectless_dispatch_trace(trace)?;
    if trace.phase != EffectlessDispatchPhase::Prepared {
        return Err("fixture dispatch requires a prepared trace".to_owned());
    }
    let mut successor = trace.clone();
    successor.phase = EffectlessDispatchPhase::FixtureDispatchRecorded;
    successor.transition_sequence = 1;
    successor.fixture_dispatch = Some(EffectlessFixtureDispatchRecord {
        profile: EFFECTLESS_FIXTURE_DISPATCH_PROFILE.to_owned(),
        fixture_route: FIXTURE_ROUTE.to_owned(),
        envelope_digest: trace.envelope_digest.clone(),
        provider_execution_claimed: false,
    });
    validate_effectless_dispatch_trace(&successor)?;
    Ok(successor)
}

pub fn record_effectless_fixture_response(
    trace: &EffectlessDispatchTrace,
    supplied_response: &Value,
) -> Result<EffectlessDispatchTrace, String> {
    validate_effectless_dispatch_trace(trace)?;
    if trace.phase != EffectlessDispatchPhase::FixtureDispatchRecorded {
        return Err("fixture response requires recorded fixture dispatch".to_owned());
    }
    if !supplied_response.is_object() {
        return Err("fixture response must be one JSON object".to_owned());
    }
    let mut successor = trace.clone();
    successor.phase = EffectlessDispatchPhase::FixtureResponseRecorded;
    successor.transition_sequence = 2;
    successor.supplied_response = Some(supplied_response.clone());
    successor.response_digest = Some(digest_json(RESPONSE_DIGEST_DOMAIN, supplied_response)?);
    validate_effectless_dispatch_trace(&successor)?;
    Ok(successor)
}

pub fn admit_iteration_effectless_dispatch(
    trace: &EffectlessDispatchTrace,
    transport: &AttentionTransportRecord,
) -> Result<EffectlessDispatchTrace, String> {
    validate_response_recorded(trace)?;
    validate_iteration_transport_envelope_against(&trace.envelope, transport)?;
    if trace.supplied_response.as_ref() != Some(&transport.sanitized_response) {
        return Err("supplied response differs from canonical iteration response".to_owned());
    }
    admitted_successor(trace)
}

pub fn admit_terminal_effectless_dispatch(
    trace: &EffectlessDispatchTrace,
    transport: &TerminalReflectionTransport,
) -> Result<EffectlessDispatchTrace, String> {
    validate_response_recorded(trace)?;
    validate_terminal_transport_envelope_against(&trace.envelope, transport)?;
    if trace.supplied_response.as_ref() != Some(&transport.sanitized_response) {
        return Err("supplied response differs from canonical terminal response".to_owned());
    }
    admitted_successor(trace)
}

pub fn validate_effectless_dispatch_trace(trace: &EffectlessDispatchTrace) -> Result<(), String> {
    if trace.profile != EFFECTLESS_DISPATCH_TRACE_PROFILE
        || trace.provider_execution_claimed
        || trace.external_effect_claimed
        || trace.persistence_claimed
        || trace.nonclaims != trace_nonclaims()
    {
        return Err("effectless dispatch trace identity or claims are invalid".to_owned());
    }
    validate_attention_transport_envelope(&trace.envelope)?;
    if trace.envelope_digest != digest_json(ENVELOPE_DIGEST_DOMAIN, &trace.envelope)? {
        return Err("effectless dispatch envelope digest differs from envelope".to_owned());
    }
    let expected_sequence = match trace.phase {
        EffectlessDispatchPhase::Prepared => 0,
        EffectlessDispatchPhase::FixtureDispatchRecorded => 1,
        EffectlessDispatchPhase::FixtureResponseRecorded => 2,
        EffectlessDispatchPhase::Admitted => 3,
    };
    if trace.transition_sequence != expected_sequence {
        return Err("effectless dispatch transition sequence differs from phase".to_owned());
    }
    let dispatch_expected = trace.phase != EffectlessDispatchPhase::Prepared;
    if trace.fixture_dispatch.is_some() != dispatch_expected {
        return Err("effectless dispatch marker presence differs from phase".to_owned());
    }
    if let Some(dispatch) = &trace.fixture_dispatch
        && (dispatch.profile != EFFECTLESS_FIXTURE_DISPATCH_PROFILE
            || dispatch.fixture_route != FIXTURE_ROUTE
            || dispatch.envelope_digest != trace.envelope_digest
            || dispatch.provider_execution_claimed)
    {
        return Err("effectless fixture dispatch marker is invalid".to_owned());
    }
    let response_expected = matches!(
        trace.phase,
        EffectlessDispatchPhase::FixtureResponseRecorded | EffectlessDispatchPhase::Admitted
    );
    if trace.supplied_response.is_some() != response_expected
        || trace.response_digest.is_some() != response_expected
        || trace.canonical_admission_recorded != (trace.phase == EffectlessDispatchPhase::Admitted)
    {
        return Err(
            "effectless dispatch response or admission fields differ from phase".to_owned(),
        );
    }
    if let (Some(response), Some(response_digest)) =
        (&trace.supplied_response, &trace.response_digest)
        && (!response.is_object()
            || response_digest != &digest_json(RESPONSE_DIGEST_DOMAIN, response)?)
    {
        return Err("effectless supplied response commitment is invalid".to_owned());
    }
    Ok(())
}

pub fn generate_scripted_effectless_dispatch_run() -> Result<ScriptedEffectlessDispatchRun, String>
{
    let source_envelopes = generate_scripted_transport_envelope_set()?;
    let mut iteration_traces = Vec::with_capacity(source_envelopes.iteration_envelopes.len());
    for (envelope, transport) in source_envelopes
        .iteration_envelopes
        .iter()
        .zip(&source_envelopes.source_projection.iteration_transports)
    {
        let prepared = prepare_effectless_dispatch(envelope)?;
        let dispatched = record_effectless_fixture_dispatch(&prepared)?;
        let received =
            record_effectless_fixture_response(&dispatched, &transport.sanitized_response)?;
        iteration_traces.push(admit_iteration_effectless_dispatch(&received, transport)?);
    }
    let terminal_transport = &source_envelopes
        .source_projection
        .terminal_reflection_transport;
    let terminal_prepared =
        prepare_effectless_dispatch(&source_envelopes.terminal_reflection_envelope)?;
    let terminal_dispatched = record_effectless_fixture_dispatch(&terminal_prepared)?;
    let terminal_received = record_effectless_fixture_response(
        &terminal_dispatched,
        &terminal_transport.sanitized_response,
    )?;
    let terminal_reflection_trace =
        admit_terminal_effectless_dispatch(&terminal_received, terminal_transport)?;
    let admitted_trace_count = iteration_traces
        .len()
        .checked_add(1)
        .ok_or_else(|| "effectless admitted trace count overflow".to_owned())?;
    let run = ScriptedEffectlessDispatchRun {
        profile: SCRIPTED_EFFECTLESS_DISPATCH_RUN_PROFILE.to_owned(),
        source_envelopes,
        iteration_traces,
        terminal_reflection_trace,
        admitted_trace_count,
        all_admitted: true,
        provider_execution_claimed: false,
        external_effect_claimed: false,
        semantic_equivalence_claimed: false,
        nonclaims: run_nonclaims(),
    };
    validate_scripted_effectless_dispatch_run(&run)?;
    Ok(run)
}

pub fn validate_scripted_effectless_dispatch_run(
    run: &ScriptedEffectlessDispatchRun,
) -> Result<(), String> {
    if run.profile != SCRIPTED_EFFECTLESS_DISPATCH_RUN_PROFILE
        || !run.all_admitted
        || run.provider_execution_claimed
        || run.external_effect_claimed
        || run.semantic_equivalence_claimed
        || run.nonclaims != run_nonclaims()
    {
        return Err("scripted effectless dispatch run identity or claims are invalid".to_owned());
    }
    validate_scripted_transport_envelope_set(&run.source_envelopes)?;
    if run.iteration_traces.len() != run.source_envelopes.iteration_envelopes.len()
        || run.admitted_trace_count
            != run
                .iteration_traces
                .len()
                .checked_add(1)
                .ok_or_else(|| "effectless admitted trace count overflow".to_owned())?
    {
        return Err("scripted effectless dispatch trace count is invalid".to_owned());
    }
    for ((trace, envelope), transport) in run
        .iteration_traces
        .iter()
        .zip(&run.source_envelopes.iteration_envelopes)
        .zip(&run.source_envelopes.source_projection.iteration_transports)
    {
        let expected = complete_iteration_trace(envelope, transport)?;
        if trace != &expected {
            return Err(
                "scripted effectless iteration trace differs from reconstruction".to_owned(),
            );
        }
    }
    let expected_terminal = complete_terminal_trace(
        &run.source_envelopes.terminal_reflection_envelope,
        &run.source_envelopes
            .source_projection
            .terminal_reflection_transport,
    )?;
    if run.terminal_reflection_trace != expected_terminal {
        return Err("scripted effectless terminal trace differs from reconstruction".to_owned());
    }
    Ok(())
}

pub fn pretty_scripted_effectless_dispatch_run_bytes(
    run: &ScriptedEffectlessDispatchRun,
) -> Result<Vec<u8>, String> {
    validate_scripted_effectless_dispatch_run(run)?;
    let mut bytes = serde_json::to_vec_pretty(run)
        .map_err(|error| format!("effectless dispatch serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn complete_iteration_trace(
    envelope: &AttentionTransportEnvelope,
    transport: &AttentionTransportRecord,
) -> Result<EffectlessDispatchTrace, String> {
    let prepared = prepare_effectless_dispatch(envelope)?;
    let dispatched = record_effectless_fixture_dispatch(&prepared)?;
    let received = record_effectless_fixture_response(&dispatched, &transport.sanitized_response)?;
    admit_iteration_effectless_dispatch(&received, transport)
}

fn complete_terminal_trace(
    envelope: &AttentionTransportEnvelope,
    transport: &TerminalReflectionTransport,
) -> Result<EffectlessDispatchTrace, String> {
    let prepared = prepare_effectless_dispatch(envelope)?;
    let dispatched = record_effectless_fixture_dispatch(&prepared)?;
    let received = record_effectless_fixture_response(&dispatched, &transport.sanitized_response)?;
    admit_terminal_effectless_dispatch(&received, transport)
}

fn validate_response_recorded(trace: &EffectlessDispatchTrace) -> Result<(), String> {
    validate_effectless_dispatch_trace(trace)?;
    if trace.phase != EffectlessDispatchPhase::FixtureResponseRecorded {
        return Err("canonical admission requires a recorded fixture response".to_owned());
    }
    Ok(())
}

fn admitted_successor(trace: &EffectlessDispatchTrace) -> Result<EffectlessDispatchTrace, String> {
    let mut successor = trace.clone();
    successor.phase = EffectlessDispatchPhase::Admitted;
    successor.transition_sequence = 3;
    successor.canonical_admission_recorded = true;
    validate_effectless_dispatch_trace(&successor)?;
    Ok(successor)
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("effectless dispatch digest serialization failed: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(ContentDigest {
        algorithm: "sha256".to_owned(),
        value: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

fn trace_nonclaims() -> Vec<String> {
    EFFECTLESS_DISPATCH_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn run_nonclaims() -> Vec<String> {
    SCRIPTED_EFFECTLESS_DISPATCH_RUN_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
