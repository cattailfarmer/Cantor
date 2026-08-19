//! Deterministic byte measurement for the staged provider-shaped transcript.

use serde::{Deserialize, Serialize};

use crate::{
    IterationSuccessor, IterativeProviderPhase, generate_scripted_terminal_pending_fixture,
    scripted_terminal_reflection_response,
};

pub const ITERATIVE_TRANSCRIPT_MEASUREMENT_PROFILE: &str =
    "cantor-iterative-transcript-measurement/0.1";
pub const ITERATIVE_TRANSCRIPT_MEASUREMENT_NONCLAIMS: [&str; 6] = [
    "compact UTF-8 JSON bytes are not model tokens",
    "serialization bytes are not latency memory or context utilization",
    "measurement is not reasoning quality accuracy or generalization evidence",
    "fixture envelopes are synthesized evidence not provider output",
    "no provider network model process or external effect was used",
    "exact registry and record custody is not model-facing transcript",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderPassByteMeasurement {
    pub pass_index: u32,
    pub phase: IterativeProviderPhase,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub cumulative_request_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IterativeTranscriptMeasurement {
    pub profile: String,
    pub fixture: String,
    pub passes: Vec<ProviderPassByteMeasurement>,
    pub total_request_bytes: usize,
    pub total_response_bytes: usize,
    pub total_model_facing_exchange_bytes: usize,
    pub ready_projection_bytes: usize,
    pub terminal_projection_bytes: usize,
    pub unique_projection_bytes: usize,
    pub terminal_observation_bytes: usize,
    pub terminal_record_json_bytes: usize,
    pub successor_registry_bytes: usize,
    pub exact_terminal_custody_bytes: usize,
    pub pending_run_bytes: usize,
    pub complete_run_bytes: usize,
    pub final_request_growth_from_first_basis_points: u64,
    pub model_facing_exchange_share_of_complete_basis_points: u64,
    pub unique_projection_share_of_exact_custody_basis_points: u64,
    pub byte_basis: String,
    pub nonclaims: Vec<String>,
}

pub fn generate_iterative_transcript_measurement() -> Result<IterativeTranscriptMeasurement, String>
{
    let pending = generate_scripted_terminal_pending_fixture()?;
    let final_response = scripted_terminal_reflection_response(&pending.report.terminal_projection);
    let complete = crate::admit_scripted_terminal_reflection(&pending, &final_response)?;

    let mut passes = Vec::with_capacity(pending.report.iterations.len() + 1);
    let mut cumulative_request_bytes = 0_usize;
    for (index, iteration) in pending.report.iterations.iter().enumerate() {
        let request_bytes = compact_json_bytes(&iteration.request)?;
        cumulative_request_bytes = cumulative_request_bytes
            .checked_add(request_bytes)
            .ok_or_else(|| "transcript request-byte sum overflow".to_owned())?;
        passes.push(ProviderPassByteMeasurement {
            pass_index: u32::try_from(index)
                .map_err(|_| "transcript pass index cannot be represented".to_owned())?,
            phase: IterativeProviderPhase::Advance,
            request_bytes,
            response_bytes: compact_json_bytes(&iteration.sanitized_response)?,
            cumulative_request_bytes,
        });
    }
    let reflection_request_bytes = compact_json_bytes(&pending.terminal_reflection_request)?;
    cumulative_request_bytes = cumulative_request_bytes
        .checked_add(reflection_request_bytes)
        .ok_or_else(|| "transcript request-byte sum overflow".to_owned())?;
    passes.push(ProviderPassByteMeasurement {
        pass_index: u32::try_from(passes.len())
            .map_err(|_| "transcript pass index cannot be represented".to_owned())?,
        phase: IterativeProviderPhase::ReflectTerminal,
        request_bytes: reflection_request_bytes,
        response_bytes: compact_json_bytes(&complete.sanitized_terminal_reflection_response)?,
        cumulative_request_bytes,
    });

    let total_request_bytes = checked_sum(passes.iter().map(|pass| pass.request_bytes))?;
    let total_response_bytes = checked_sum(passes.iter().map(|pass| pass.response_bytes))?;
    let total_model_facing_exchange_bytes =
        total_request_bytes
            .checked_add(total_response_bytes)
            .ok_or_else(|| "transcript exchange-byte sum overflow".to_owned())?;
    let mut ready_projection_bytes = 0_usize;
    for iteration in &pending.report.iterations {
        if let IterationSuccessor::Ready { projection } = &iteration.successor {
            ready_projection_bytes = ready_projection_bytes
                .checked_add(compact_json_bytes(projection)?)
                .ok_or_else(|| "READY projection-byte sum overflow".to_owned())?;
        }
    }
    let terminal_projection_bytes = compact_json_bytes(&pending.report.terminal_projection)?;
    let unique_projection_bytes = ready_projection_bytes
        .checked_add(terminal_projection_bytes)
        .ok_or_else(|| "projection-byte sum overflow".to_owned())?;
    let terminal_observation_bytes = compact_json_bytes(&pending.report.terminal_observation)?;
    let terminal_record_json_bytes = pending.report.terminal_observation.record_json.len();
    let successor_registry_bytes = compact_json_bytes(&pending.successor_registry)?;
    let exact_terminal_custody_bytes = terminal_observation_bytes
        .checked_add(successor_registry_bytes)
        .ok_or_else(|| "terminal custody-byte sum overflow".to_owned())?;
    let pending_run_bytes = compact_json_bytes(&pending)?;
    let complete_run_bytes = compact_json_bytes(&complete)?;
    let first_request_bytes = passes
        .first()
        .ok_or_else(|| "transcript measurement omitted first pass".to_owned())?
        .request_bytes;
    let final_request_bytes = passes
        .last()
        .ok_or_else(|| "transcript measurement omitted final pass".to_owned())?
        .request_bytes;
    let measurement = IterativeTranscriptMeasurement {
        profile: ITERATIVE_TRANSCRIPT_MEASUREMENT_PROFILE.to_owned(),
        fixture: "scripted_terminal_pending_quota8_v1".to_owned(),
        passes,
        total_request_bytes,
        total_response_bytes,
        total_model_facing_exchange_bytes,
        ready_projection_bytes,
        terminal_projection_bytes,
        unique_projection_bytes,
        terminal_observation_bytes,
        terminal_record_json_bytes,
        successor_registry_bytes,
        exact_terminal_custody_bytes,
        pending_run_bytes,
        complete_run_bytes,
        final_request_growth_from_first_basis_points: growth_basis_points(
            first_request_bytes,
            final_request_bytes,
        )?,
        model_facing_exchange_share_of_complete_basis_points: share_basis_points(
            total_model_facing_exchange_bytes,
            complete_run_bytes,
        )?,
        unique_projection_share_of_exact_custody_basis_points: share_basis_points(
            unique_projection_bytes,
            exact_terminal_custody_bytes,
        )?,
        byte_basis: "compact UTF-8 JSON for typed values; terminal_record_json_bytes counts the exact retained UTF-8 record body; cumulative requests represent separate stateless provider-shaped passes".to_owned(),
        nonclaims: measurement_nonclaims(),
    };
    validate_iterative_transcript_measurement(&measurement)?;
    Ok(measurement)
}

pub fn validate_iterative_transcript_measurement(
    measurement: &IterativeTranscriptMeasurement,
) -> Result<(), String> {
    if measurement.profile != ITERATIVE_TRANSCRIPT_MEASUREMENT_PROFILE
        || measurement.fixture != "scripted_terminal_pending_quota8_v1"
        || measurement.passes.len() != 3
        || measurement.nonclaims != measurement_nonclaims()
        || measurement.byte_basis
            != "compact UTF-8 JSON for typed values; terminal_record_json_bytes counts the exact retained UTF-8 record body; cumulative requests represent separate stateless provider-shaped passes"
    {
        return Err("iterative transcript measurement identity is invalid".to_owned());
    }
    let mut cumulative = 0_usize;
    for (index, pass) in measurement.passes.iter().enumerate() {
        let expected_phase = if index + 1 == measurement.passes.len() {
            IterativeProviderPhase::ReflectTerminal
        } else {
            IterativeProviderPhase::Advance
        };
        cumulative = cumulative
            .checked_add(pass.request_bytes)
            .ok_or_else(|| "transcript request-byte validation overflow".to_owned())?;
        if usize::try_from(pass.pass_index).ok() != Some(index)
            || pass.phase != expected_phase
            || pass.request_bytes == 0
            || pass.response_bytes == 0
            || pass.cumulative_request_bytes != cumulative
        {
            return Err("iterative transcript pass ordering or bytes are invalid".to_owned());
        }
    }
    let total_request_bytes =
        checked_sum(measurement.passes.iter().map(|pass| pass.request_bytes))?;
    let total_response_bytes =
        checked_sum(measurement.passes.iter().map(|pass| pass.response_bytes))?;
    if measurement.total_request_bytes != total_request_bytes
        || measurement.total_response_bytes != total_response_bytes
        || measurement.total_model_facing_exchange_bytes
            != total_request_bytes
                .checked_add(total_response_bytes)
                .ok_or_else(|| "transcript exchange-byte validation overflow".to_owned())?
        || measurement.unique_projection_bytes
            != measurement
                .ready_projection_bytes
                .checked_add(measurement.terminal_projection_bytes)
                .ok_or_else(|| "projection-byte validation overflow".to_owned())?
        || measurement.exact_terminal_custody_bytes
            != measurement
                .terminal_observation_bytes
                .checked_add(measurement.successor_registry_bytes)
                .ok_or_else(|| "terminal custody-byte validation overflow".to_owned())?
    {
        return Err("iterative transcript aggregate arithmetic is invalid".to_owned());
    }
    let sizes = [
        measurement.ready_projection_bytes,
        measurement.terminal_projection_bytes,
        measurement.terminal_observation_bytes,
        measurement.terminal_record_json_bytes,
        measurement.successor_registry_bytes,
        measurement.pending_run_bytes,
        measurement.complete_run_bytes,
    ];
    if sizes.contains(&0)
        || measurement.terminal_record_json_bytes >= measurement.terminal_observation_bytes
        || measurement.unique_projection_bytes >= measurement.exact_terminal_custody_bytes
        || measurement.total_model_facing_exchange_bytes >= measurement.complete_run_bytes
    {
        return Err("iterative transcript measurement size relationships are invalid".to_owned());
    }
    let first = measurement.passes[0].request_bytes;
    let final_request = measurement.passes[2].request_bytes;
    if measurement.final_request_growth_from_first_basis_points
        != growth_basis_points(first, final_request)?
        || measurement.model_facing_exchange_share_of_complete_basis_points
            != share_basis_points(
                measurement.total_model_facing_exchange_bytes,
                measurement.complete_run_bytes,
            )?
        || measurement.unique_projection_share_of_exact_custody_basis_points
            != share_basis_points(
                measurement.unique_projection_bytes,
                measurement.exact_terminal_custody_bytes,
            )?
    {
        return Err("iterative transcript measurement ratios are invalid".to_owned());
    }
    Ok(())
}

pub fn pretty_iterative_transcript_measurement_bytes(
    measurement: &IterativeTranscriptMeasurement,
) -> Result<Vec<u8>, String> {
    validate_iterative_transcript_measurement(measurement)?;
    let mut bytes = serde_json::to_vec_pretty(measurement)
        .map_err(|error| format!("transcript measurement serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compact_json_bytes(value: &impl Serialize) -> Result<usize, String> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("transcript measurement value serialization failed: {error}"))
}

fn checked_sum(values: impl IntoIterator<Item = usize>) -> Result<usize, String> {
    values.into_iter().try_fold(0_usize, |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| "transcript measurement sum overflow".to_owned())
    })
}

fn share_basis_points(numerator: usize, denominator: usize) -> Result<u64, String> {
    if denominator == 0 || numerator > denominator {
        return Err("transcript measurement share is outside its basis".to_owned());
    }
    let scaled = (numerator as u128)
        .checked_mul(10_000)
        .ok_or_else(|| "transcript measurement share overflow".to_owned())?
        / denominator as u128;
    u64::try_from(scaled).map_err(|_| "transcript measurement share overflow".to_owned())
}

fn growth_basis_points(baseline: usize, observed: usize) -> Result<u64, String> {
    if baseline == 0 || observed < baseline {
        return Err("transcript request growth is outside its basis".to_owned());
    }
    let increase = observed - baseline;
    let scaled = (increase as u128)
        .checked_mul(10_000)
        .ok_or_else(|| "transcript request growth overflow".to_owned())?
        / baseline as u128;
    u64::try_from(scaled).map_err(|_| "transcript request growth overflow".to_owned())
}

fn measurement_nonclaims() -> Vec<String> {
    ITERATIVE_TRANSCRIPT_MEASUREMENT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
