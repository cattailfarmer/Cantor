//! Minimal host-custody handles and byte measurement for dispatch checkpoints.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    DispatchCheckpointNextOperation, DispatchLifecycleCheckpoint, EffectlessDispatchPhase,
    generate_scripted_dispatch_resume_corpus, validate_dispatch_lifecycle_checkpoint,
};

pub const DISPATCH_CHECKPOINT_HANDLE_PROFILE: &str = "cantor-dispatch-checkpoint-handle/0.1";
pub const DISPATCH_CHECKPOINT_HANDLE_MEASUREMENT_PROFILE: &str =
    "cantor-dispatch-checkpoint-handle-measurement/0.1";
pub const DISPATCH_CHECKPOINT_HANDLE_NONCLAIMS: [&str; 5] = [
    "handle is not independently resumable without host checkpoint custody",
    "host-custody flag is structural fixture evidence not physical storage proof",
    "content commitments are not producer authentication",
    "handle does not contain a trace request response hidden state or KV cache",
    "handle construction is not provider execution or semantic equivalence",
];
pub const DISPATCH_CHECKPOINT_HANDLE_MEASUREMENT_NONCLAIMS: [&str; 5] = [
    "compact UTF-8 JSON bytes are not model tokens",
    "byte size is not latency memory accuracy quality or compatibility evidence",
    "source checkpoints remain authoritative under host custody",
    "fixture values are synthesized and not provider output",
    "no model process network persistence hidden-state or external-effect operation",
];

const CHECKPOINT_DIGEST_DOMAIN: &str = "cantor.dispatch-checkpoint-handle.checkpoint.v1";
const CORPUS_DIGEST_DOMAIN: &str = "cantor.dispatch-checkpoint-handle.corpus.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchCheckpointHandle {
    pub profile: String,
    pub checkpoint_phase: EffectlessDispatchPhase,
    pub next_operation: DispatchCheckpointNextOperation,
    pub transport_position: u32,
    pub terminal_reflection: bool,
    pub checkpoint_digest: ContentDigest,
    pub envelope_digest: ContentDigest,
    pub response_digest: Option<ContentDigest>,
    pub exact_checkpoint_under_host_custody: bool,
    pub serialized_checkpoint_embedded: bool,
    pub persistence_claimed: bool,
    pub producer_authentication_claimed: bool,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchCheckpointHandleByteCase {
    pub case_ordinal: u32,
    pub checkpoint_phase: EffectlessDispatchPhase,
    pub terminal_reflection: bool,
    pub handle: DispatchCheckpointHandle,
    pub full_checkpoint_bytes: usize,
    pub handle_bytes: usize,
    pub full_minus_handle_bytes: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DispatchCheckpointHandleMeasurement {
    pub profile: String,
    pub source_resume_corpus_digest: ContentDigest,
    pub cases: Vec<DispatchCheckpointHandleByteCase>,
    pub case_count: usize,
    pub total_full_checkpoint_bytes: usize,
    pub total_handle_bytes: usize,
    pub total_full_minus_handle_bytes: i64,
    pub minimum_handle_bytes: usize,
    pub maximum_handle_bytes: usize,
    pub handle_to_checkpoint_basis_points: u64,
    pub all_handles_smaller: bool,
    pub byte_basis: String,
    pub provider_compatibility_claimed: bool,
    pub semantic_equivalence_claimed: bool,
    pub persistence_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn compile_dispatch_checkpoint_handle(
    checkpoint: &DispatchLifecycleCheckpoint,
    transport_position: u32,
    terminal_reflection: bool,
) -> Result<DispatchCheckpointHandle, String> {
    validate_dispatch_lifecycle_checkpoint(checkpoint)?;
    let handle = DispatchCheckpointHandle {
        profile: DISPATCH_CHECKPOINT_HANDLE_PROFILE.to_owned(),
        checkpoint_phase: checkpoint.trace.phase,
        next_operation: checkpoint.next_operation,
        transport_position,
        terminal_reflection,
        checkpoint_digest: digest_json(CHECKPOINT_DIGEST_DOMAIN, checkpoint)?,
        envelope_digest: checkpoint.trace.envelope_digest.clone(),
        response_digest: checkpoint.trace.response_digest.clone(),
        exact_checkpoint_under_host_custody: true,
        serialized_checkpoint_embedded: false,
        persistence_claimed: false,
        producer_authentication_claimed: false,
        nonclaims: handle_nonclaims(),
    };
    validate_dispatch_checkpoint_handle(&handle)?;
    Ok(handle)
}

pub fn validate_dispatch_checkpoint_handle(
    handle: &DispatchCheckpointHandle,
) -> Result<(), String> {
    if handle.profile != DISPATCH_CHECKPOINT_HANDLE_PROFILE
        || !handle.exact_checkpoint_under_host_custody
        || handle.serialized_checkpoint_embedded
        || handle.persistence_claimed
        || handle.producer_authentication_claimed
        || handle.nonclaims != handle_nonclaims()
        || !valid_sha256(&handle.checkpoint_digest)
        || !valid_sha256(&handle.envelope_digest)
        || handle
            .response_digest
            .as_ref()
            .is_some_and(|digest| !valid_sha256(digest))
    {
        return Err("dispatch checkpoint handle identity claims or digests are invalid".to_owned());
    }
    let response_expected = matches!(
        handle.checkpoint_phase,
        EffectlessDispatchPhase::FixtureResponseRecorded | EffectlessDispatchPhase::Admitted
    );
    if handle.response_digest.is_some() != response_expected
        || handle.next_operation != next_operation(handle.checkpoint_phase)
    {
        return Err("dispatch checkpoint handle phase shape is invalid".to_owned());
    }
    Ok(())
}

pub fn validate_dispatch_checkpoint_handle_against(
    handle: &DispatchCheckpointHandle,
    checkpoint: &DispatchLifecycleCheckpoint,
    expected_transport_position: u32,
    expected_terminal_reflection: bool,
) -> Result<(), String> {
    validate_dispatch_checkpoint_handle(handle)?;
    let expected = compile_dispatch_checkpoint_handle(
        checkpoint,
        expected_transport_position,
        expected_terminal_reflection,
    )?;
    if handle != &expected {
        return Err("dispatch checkpoint handle differs from exact checkpoint binding".to_owned());
    }
    Ok(())
}

pub fn generate_dispatch_checkpoint_handle_measurement()
-> Result<DispatchCheckpointHandleMeasurement, String> {
    let corpus = generate_scripted_dispatch_resume_corpus()?;
    let mut cases = Vec::with_capacity(corpus.cases.len());
    for case in &corpus.cases {
        let handle = compile_dispatch_checkpoint_handle(
            &case.checkpoint,
            case.transport_position,
            case.terminal_reflection,
        )?;
        let full_checkpoint_bytes = compact_json_bytes(&case.checkpoint)?;
        let handle_bytes = compact_json_bytes(&handle)?;
        cases.push(DispatchCheckpointHandleByteCase {
            case_ordinal: case.case_ordinal,
            checkpoint_phase: case.checkpoint_phase,
            terminal_reflection: case.terminal_reflection,
            handle,
            full_checkpoint_bytes,
            handle_bytes,
            full_minus_handle_bytes: signed_difference(full_checkpoint_bytes, handle_bytes)?,
        });
    }
    let total_full_checkpoint_bytes =
        checked_sum(cases.iter().map(|case| case.full_checkpoint_bytes))?;
    let total_handle_bytes = checked_sum(cases.iter().map(|case| case.handle_bytes))?;
    let minimum_handle_bytes = cases
        .iter()
        .map(|case| case.handle_bytes)
        .min()
        .ok_or_else(|| "checkpoint handle measurement has no cases".to_owned())?;
    let maximum_handle_bytes = cases
        .iter()
        .map(|case| case.handle_bytes)
        .max()
        .ok_or_else(|| "checkpoint handle measurement has no cases".to_owned())?;
    let measurement = DispatchCheckpointHandleMeasurement {
        profile: DISPATCH_CHECKPOINT_HANDLE_MEASUREMENT_PROFILE.to_owned(),
        source_resume_corpus_digest: digest_json(CORPUS_DIGEST_DOMAIN, &corpus)?,
        case_count: cases.len(),
        total_full_checkpoint_bytes,
        total_handle_bytes,
        total_full_minus_handle_bytes: signed_difference(
            total_full_checkpoint_bytes,
            total_handle_bytes,
        )?,
        minimum_handle_bytes,
        maximum_handle_bytes,
        handle_to_checkpoint_basis_points: basis_points(
            total_handle_bytes,
            total_full_checkpoint_bytes,
        )?,
        all_handles_smaller: cases
            .iter()
            .all(|case| case.full_checkpoint_bytes > case.handle_bytes),
        cases,
        byte_basis: "compact UTF-8 JSON values; full_minus_handle is signed full checkpoint bytes minus host-custody handle bytes".to_owned(),
        provider_compatibility_claimed: false,
        semantic_equivalence_claimed: false,
        persistence_claimed: false,
        nonclaims: measurement_nonclaims(),
    };
    validate_dispatch_checkpoint_handle_measurement(&measurement)?;
    Ok(measurement)
}

pub fn validate_dispatch_checkpoint_handle_measurement(
    measurement: &DispatchCheckpointHandleMeasurement,
) -> Result<(), String> {
    if measurement.profile != DISPATCH_CHECKPOINT_HANDLE_MEASUREMENT_PROFILE
        || measurement.provider_compatibility_claimed
        || measurement.semantic_equivalence_claimed
        || measurement.persistence_claimed
        || measurement.nonclaims != measurement_nonclaims()
        || measurement.byte_basis
            != "compact UTF-8 JSON values; full_minus_handle is signed full checkpoint bytes minus host-custody handle bytes"
    {
        return Err("checkpoint handle measurement identity or claims are invalid".to_owned());
    }
    let corpus = generate_scripted_dispatch_resume_corpus()?;
    if measurement.source_resume_corpus_digest != digest_json(CORPUS_DIGEST_DOMAIN, &corpus)?
        || measurement.case_count != corpus.cases.len()
        || measurement.cases.len() != corpus.cases.len()
    {
        return Err("checkpoint handle measurement source identity is invalid".to_owned());
    }
    for (measured, source) in measurement.cases.iter().zip(&corpus.cases) {
        validate_dispatch_checkpoint_handle_against(
            &measured.handle,
            &source.checkpoint,
            source.transport_position,
            source.terminal_reflection,
        )?;
        let full_bytes = compact_json_bytes(&source.checkpoint)?;
        let handle_bytes = compact_json_bytes(&measured.handle)?;
        if measured.case_ordinal != source.case_ordinal
            || measured.checkpoint_phase != source.checkpoint_phase
            || measured.terminal_reflection != source.terminal_reflection
            || measured.full_checkpoint_bytes != full_bytes
            || measured.handle_bytes != handle_bytes
            || measured.full_minus_handle_bytes != signed_difference(full_bytes, handle_bytes)?
        {
            return Err("checkpoint handle byte case differs from reconstruction".to_owned());
        }
    }
    let total_full = checked_sum(
        measurement
            .cases
            .iter()
            .map(|case| case.full_checkpoint_bytes),
    )?;
    let total_handle = checked_sum(measurement.cases.iter().map(|case| case.handle_bytes))?;
    let minimum = measurement
        .cases
        .iter()
        .map(|case| case.handle_bytes)
        .min()
        .ok_or_else(|| "checkpoint handle measurement has no cases".to_owned())?;
    let maximum = measurement
        .cases
        .iter()
        .map(|case| case.handle_bytes)
        .max()
        .ok_or_else(|| "checkpoint handle measurement has no cases".to_owned())?;
    if measurement.total_full_checkpoint_bytes != total_full
        || measurement.total_handle_bytes != total_handle
        || measurement.total_full_minus_handle_bytes != signed_difference(total_full, total_handle)?
        || measurement.minimum_handle_bytes != minimum
        || measurement.maximum_handle_bytes != maximum
        || measurement.handle_to_checkpoint_basis_points != basis_points(total_handle, total_full)?
        || measurement.all_handles_smaller
            != measurement
                .cases
                .iter()
                .all(|case| case.full_checkpoint_bytes > case.handle_bytes)
    {
        return Err("checkpoint handle measurement aggregate differs from cases".to_owned());
    }
    Ok(())
}

pub fn pretty_dispatch_checkpoint_handle_measurement_bytes(
    measurement: &DispatchCheckpointHandleMeasurement,
) -> Result<Vec<u8>, String> {
    validate_dispatch_checkpoint_handle_measurement(measurement)?;
    let mut bytes = serde_json::to_vec_pretty(measurement)
        .map_err(|error| format!("checkpoint handle measurement serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
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

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("checkpoint handle digest serialization failed: {error}"))?;
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

fn valid_sha256(digest: &ContentDigest) -> bool {
    digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest
            .value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn compact_json_bytes<T: Serialize>(value: &T) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("checkpoint handle byte serialization failed: {error}"))
}

fn checked_sum(values: impl IntoIterator<Item = usize>) -> Result<usize, String> {
    values.into_iter().try_fold(0_usize, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| "checkpoint handle byte sum overflow".to_owned())
    })
}

fn signed_difference(left: usize, right: usize) -> Result<i64, String> {
    let left = i64::try_from(left)
        .map_err(|_| "checkpoint handle byte count cannot fit i64".to_owned())?;
    let right = i64::try_from(right)
        .map_err(|_| "checkpoint handle byte count cannot fit i64".to_owned())?;
    left.checked_sub(right)
        .ok_or_else(|| "checkpoint handle byte difference overflow".to_owned())
}

fn basis_points(numerator: usize, denominator: usize) -> Result<u64, String> {
    if denominator == 0 {
        return Err("checkpoint handle basis-point denominator is zero".to_owned());
    }
    let numerator = u128::try_from(numerator)
        .map_err(|_| "checkpoint handle numerator cannot fit u128".to_owned())?;
    let denominator = u128::try_from(denominator)
        .map_err(|_| "checkpoint handle denominator cannot fit u128".to_owned())?;
    let scaled = numerator
        .checked_mul(10_000)
        .ok_or_else(|| "checkpoint handle basis-point multiplication overflow".to_owned())?
        / denominator;
    u64::try_from(scaled).map_err(|_| "checkpoint handle basis points cannot fit u64".to_owned())
}

fn handle_nonclaims() -> Vec<String> {
    DISPATCH_CHECKPOINT_HANDLE_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn measurement_nonclaims() -> Vec<String> {
    DISPATCH_CHECKPOINT_HANDLE_MEASUREMENT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
