//! Serializable pure checkpoints and exact resume comparison for dispatch lifecycles.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    AttentionTransportEnvelope, AttentionTransportRecord, EffectlessDispatchPhase,
    EffectlessDispatchTrace, ScriptedEffectlessDispatchRun, TerminalReflectionTransport,
    admit_iteration_effectless_dispatch, admit_terminal_effectless_dispatch,
    generate_scripted_effectless_dispatch_run, prepare_effectless_dispatch,
    record_effectless_fixture_dispatch, record_effectless_fixture_response,
    validate_effectless_dispatch_trace, validate_iteration_transport_envelope_against,
    validate_scripted_effectless_dispatch_run, validate_terminal_transport_envelope_against,
};

pub const DISPATCH_LIFECYCLE_CHECKPOINT_PROFILE: &str = "cantor-dispatch-lifecycle-checkpoint/0.1";
pub const SCRIPTED_DISPATCH_RESUME_CORPUS_PROFILE: &str =
    "cantor-scripted-dispatch-resume-corpus/0.1";
pub const DISPATCH_LIFECYCLE_CHECKPOINT_NONCLAIMS: [&str; 5] = [
    "checkpoint is serialized value state and not persistence evidence",
    "resume is pure fixture continuation and not process restoration",
    "checkpoint contains no hidden state or KV cache",
    "trace digest is not producer authentication",
    "exact trace equality is not semantic model-output equivalence",
];
pub const SCRIPTED_DISPATCH_RESUME_CORPUS_NONCLAIMS: [&str; 5] = [
    "all interruption and resume cases are deterministic fixture values",
    "no checkpoint was written to or loaded from persistent storage",
    "no provider process transport reconnect or model execution occurred",
    "exact equality is limited to canonical fixture traces",
    "no hidden-state remote external-effect or semantic-equivalence claim",
];

const TRACE_DIGEST_DOMAIN: &str = "cantor.dispatch-lifecycle-checkpoint.trace.v1";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DispatchCheckpointNextOperation {
    RecordFixtureDispatch,
    RecordFixtureResponse,
    AdmitCanonical,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchLifecycleCheckpoint {
    pub profile: String,
    pub trace: EffectlessDispatchTrace,
    pub trace_digest: ContentDigest,
    pub next_operation: DispatchCheckpointNextOperation,
    pub serialized_state_only: bool,
    pub persistence_claimed: bool,
    pub process_resume_claimed: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchResumeCase {
    pub case_ordinal: u32,
    pub transport_position: u32,
    pub terminal_reflection: bool,
    pub checkpoint_phase: EffectlessDispatchPhase,
    pub expected_next_operation: DispatchCheckpointNextOperation,
    pub checkpoint: DispatchLifecycleCheckpoint,
    pub resumed_trace: EffectlessDispatchTrace,
    pub uninterrupted_trace: EffectlessDispatchTrace,
    pub exactly_equivalent: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScriptedDispatchResumeCorpus {
    pub profile: String,
    pub source_run: ScriptedEffectlessDispatchRun,
    pub cases: Vec<DispatchResumeCase>,
    pub case_count: usize,
    pub all_exactly_equivalent: bool,
    pub persistence_claimed: bool,
    pub process_resume_claimed: bool,
    pub semantic_equivalence_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn compile_dispatch_lifecycle_checkpoint(
    trace: &EffectlessDispatchTrace,
) -> Result<DispatchLifecycleCheckpoint, String> {
    validate_effectless_dispatch_trace(trace)?;
    let checkpoint = DispatchLifecycleCheckpoint {
        profile: DISPATCH_LIFECYCLE_CHECKPOINT_PROFILE.to_owned(),
        trace: trace.clone(),
        trace_digest: digest_trace(trace)?,
        next_operation: next_operation(trace.phase),
        serialized_state_only: true,
        persistence_claimed: false,
        process_resume_claimed: false,
        nonclaims: checkpoint_nonclaims(),
    };
    validate_dispatch_lifecycle_checkpoint(&checkpoint)?;
    Ok(checkpoint)
}

pub fn validate_dispatch_lifecycle_checkpoint(
    checkpoint: &DispatchLifecycleCheckpoint,
) -> Result<(), String> {
    if checkpoint.profile != DISPATCH_LIFECYCLE_CHECKPOINT_PROFILE
        || !checkpoint.serialized_state_only
        || checkpoint.persistence_claimed
        || checkpoint.process_resume_claimed
        || checkpoint.nonclaims != checkpoint_nonclaims()
    {
        return Err("dispatch lifecycle checkpoint identity or claims are invalid".to_owned());
    }
    validate_effectless_dispatch_trace(&checkpoint.trace)?;
    if checkpoint.trace_digest != digest_trace(&checkpoint.trace)?
        || checkpoint.next_operation != next_operation(checkpoint.trace.phase)
    {
        return Err("dispatch lifecycle checkpoint digest or next operation is invalid".to_owned());
    }
    Ok(())
}

pub fn resume_iteration_fixture_checkpoint(
    checkpoint: &DispatchLifecycleCheckpoint,
    transport: &AttentionTransportRecord,
) -> Result<EffectlessDispatchTrace, String> {
    validate_dispatch_lifecycle_checkpoint(checkpoint)?;
    validate_iteration_transport_envelope_against(&checkpoint.trace.envelope, transport)?;
    let expected = complete_iteration_trace(&checkpoint.trace.envelope, transport)?;
    let resumed = match checkpoint.trace.phase {
        EffectlessDispatchPhase::Prepared => {
            let dispatched = record_effectless_fixture_dispatch(&checkpoint.trace)?;
            let received =
                record_effectless_fixture_response(&dispatched, &transport.sanitized_response)?;
            admit_iteration_effectless_dispatch(&received, transport)?
        }
        EffectlessDispatchPhase::FixtureDispatchRecorded => {
            let received = record_effectless_fixture_response(
                &checkpoint.trace,
                &transport.sanitized_response,
            )?;
            admit_iteration_effectless_dispatch(&received, transport)?
        }
        EffectlessDispatchPhase::FixtureResponseRecorded => {
            admit_iteration_effectless_dispatch(&checkpoint.trace, transport)?
        }
        EffectlessDispatchPhase::Admitted => checkpoint.trace.clone(),
    };
    if resumed != expected {
        return Err("resumed iteration trace differs from uninterrupted trace".to_owned());
    }
    Ok(resumed)
}

pub fn resume_terminal_fixture_checkpoint(
    checkpoint: &DispatchLifecycleCheckpoint,
    transport: &TerminalReflectionTransport,
) -> Result<EffectlessDispatchTrace, String> {
    validate_dispatch_lifecycle_checkpoint(checkpoint)?;
    validate_terminal_transport_envelope_against(&checkpoint.trace.envelope, transport)?;
    let expected = complete_terminal_trace(&checkpoint.trace.envelope, transport)?;
    let resumed = match checkpoint.trace.phase {
        EffectlessDispatchPhase::Prepared => {
            let dispatched = record_effectless_fixture_dispatch(&checkpoint.trace)?;
            let received =
                record_effectless_fixture_response(&dispatched, &transport.sanitized_response)?;
            admit_terminal_effectless_dispatch(&received, transport)?
        }
        EffectlessDispatchPhase::FixtureDispatchRecorded => {
            let received = record_effectless_fixture_response(
                &checkpoint.trace,
                &transport.sanitized_response,
            )?;
            admit_terminal_effectless_dispatch(&received, transport)?
        }
        EffectlessDispatchPhase::FixtureResponseRecorded => {
            admit_terminal_effectless_dispatch(&checkpoint.trace, transport)?
        }
        EffectlessDispatchPhase::Admitted => checkpoint.trace.clone(),
    };
    if resumed != expected {
        return Err("resumed terminal trace differs from uninterrupted trace".to_owned());
    }
    Ok(resumed)
}

pub fn generate_scripted_dispatch_resume_corpus() -> Result<ScriptedDispatchResumeCorpus, String> {
    let source_run = generate_scripted_effectless_dispatch_run()?;
    let cases = expected_cases(&source_run)?;
    let corpus = ScriptedDispatchResumeCorpus {
        profile: SCRIPTED_DISPATCH_RESUME_CORPUS_PROFILE.to_owned(),
        case_count: cases.len(),
        source_run,
        cases,
        all_exactly_equivalent: true,
        persistence_claimed: false,
        process_resume_claimed: false,
        semantic_equivalence_claimed: false,
        nonclaims: corpus_nonclaims(),
    };
    validate_scripted_dispatch_resume_corpus(&corpus)?;
    Ok(corpus)
}

pub fn validate_scripted_dispatch_resume_corpus(
    corpus: &ScriptedDispatchResumeCorpus,
) -> Result<(), String> {
    if corpus.profile != SCRIPTED_DISPATCH_RESUME_CORPUS_PROFILE
        || !corpus.all_exactly_equivalent
        || corpus.persistence_claimed
        || corpus.process_resume_claimed
        || corpus.semantic_equivalence_claimed
        || corpus.nonclaims != corpus_nonclaims()
    {
        return Err("scripted dispatch resume corpus identity or claims are invalid".to_owned());
    }
    validate_scripted_effectless_dispatch_run(&corpus.source_run)?;
    let expected = expected_cases(&corpus.source_run)?;
    if corpus.case_count != expected.len() || corpus.cases != expected {
        return Err("scripted dispatch resume cases differ from reconstruction".to_owned());
    }
    Ok(())
}

pub fn pretty_scripted_dispatch_resume_corpus_bytes(
    corpus: &ScriptedDispatchResumeCorpus,
) -> Result<Vec<u8>, String> {
    validate_scripted_dispatch_resume_corpus(corpus)?;
    let mut bytes = serde_json::to_vec_pretty(corpus)
        .map_err(|error| format!("dispatch resume corpus serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn expected_cases(
    source_run: &ScriptedEffectlessDispatchRun,
) -> Result<Vec<DispatchResumeCase>, String> {
    let source = &source_run.source_envelopes;
    let mut cases = Vec::new();
    for (position, (envelope, transport)) in source
        .iteration_envelopes
        .iter()
        .zip(&source.source_projection.iteration_transports)
        .enumerate()
    {
        let uninterrupted = complete_iteration_trace(envelope, transport)?;
        for trace in lifecycle_phases(envelope, &transport.sanitized_response, &uninterrupted)? {
            let checkpoint = compile_dispatch_lifecycle_checkpoint(&trace)?;
            let resumed = resume_iteration_fixture_checkpoint(&checkpoint, transport)?;
            cases.push(resume_case(
                cases.len(),
                position,
                false,
                checkpoint,
                resumed,
                uninterrupted.clone(),
            )?);
        }
    }
    let terminal_position = source.iteration_envelopes.len();
    let terminal_transport = &source.source_projection.terminal_reflection_transport;
    let uninterrupted =
        complete_terminal_trace(&source.terminal_reflection_envelope, terminal_transport)?;
    for trace in lifecycle_phases(
        &source.terminal_reflection_envelope,
        &terminal_transport.sanitized_response,
        &uninterrupted,
    )? {
        let checkpoint = compile_dispatch_lifecycle_checkpoint(&trace)?;
        let resumed = resume_terminal_fixture_checkpoint(&checkpoint, terminal_transport)?;
        cases.push(resume_case(
            cases.len(),
            terminal_position,
            true,
            checkpoint,
            resumed,
            uninterrupted.clone(),
        )?);
    }
    Ok(cases)
}

fn lifecycle_phases(
    envelope: &AttentionTransportEnvelope,
    response: &serde_json::Value,
    admitted: &EffectlessDispatchTrace,
) -> Result<Vec<EffectlessDispatchTrace>, String> {
    let prepared = prepare_effectless_dispatch(envelope)?;
    let dispatched = record_effectless_fixture_dispatch(&prepared)?;
    let received = record_effectless_fixture_response(&dispatched, response)?;
    Ok(vec![prepared, dispatched, received, admitted.clone()])
}

fn resume_case(
    case_ordinal: usize,
    transport_position: usize,
    terminal_reflection: bool,
    checkpoint: DispatchLifecycleCheckpoint,
    resumed_trace: EffectlessDispatchTrace,
    uninterrupted_trace: EffectlessDispatchTrace,
) -> Result<DispatchResumeCase, String> {
    Ok(DispatchResumeCase {
        case_ordinal: u32::try_from(case_ordinal)
            .map_err(|_| "dispatch resume case ordinal cannot be represented".to_owned())?,
        transport_position: u32::try_from(transport_position)
            .map_err(|_| "dispatch resume transport position cannot be represented".to_owned())?,
        terminal_reflection,
        checkpoint_phase: checkpoint.trace.phase,
        expected_next_operation: checkpoint.next_operation,
        exactly_equivalent: resumed_trace == uninterrupted_trace,
        checkpoint,
        resumed_trace,
        uninterrupted_trace,
    })
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

fn next_operation(phase: EffectlessDispatchPhase) -> DispatchCheckpointNextOperation {
    match phase {
        EffectlessDispatchPhase::Prepared => DispatchCheckpointNextOperation::RecordFixtureDispatch,
        EffectlessDispatchPhase::FixtureDispatchRecorded => {
            DispatchCheckpointNextOperation::RecordFixtureResponse
        }
        EffectlessDispatchPhase::FixtureResponseRecorded => {
            DispatchCheckpointNextOperation::AdmitCanonical
        }
        EffectlessDispatchPhase::Admitted => DispatchCheckpointNextOperation::Complete,
    }
}

fn digest_trace(trace: &EffectlessDispatchTrace) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(trace)
        .map_err(|error| format!("dispatch checkpoint trace serialization failed: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(TRACE_DIGEST_DOMAIN.as_bytes());
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

fn checkpoint_nonclaims() -> Vec<String> {
    DISPATCH_LIFECYCLE_CHECKPOINT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn corpus_nonclaims() -> Vec<String> {
    SCRIPTED_DISPATCH_RESUME_CORPUS_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
