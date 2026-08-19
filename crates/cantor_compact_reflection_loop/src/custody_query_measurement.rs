//! Paired byte measurement for compact inspection versus full custody resolution.

use cantor_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    CHECKPOINT_CUSTODY_QUERY_PROFILE, CheckpointCustodyOperation, CheckpointCustodyQuery,
    EffectlessDispatchPhase, compile_dispatch_checkpoint_handle, dispatch_checkpoint_custody_query,
    generate_scripted_checkpoint_custody_registry, generate_scripted_dispatch_resume_corpus,
    pretty_checkpoint_custody_query_bytes, pretty_checkpoint_custody_response_bytes,
    validate_scripted_checkpoint_custody_registry,
};

pub const CUSTODY_QUERY_SURFACE_MEASUREMENT_PROFILE: &str =
    "cantor-custody-query-surface-measurement/0.1";
pub const CUSTODY_QUERY_SURFACE_MEASUREMENT_NONCLAIMS: [&str; 6] = [
    "compact UTF-8 JSON bytes are not model tokens",
    "byte size is not latency runtime memory speed accuracy or quality evidence",
    "fixture response size is not live provider or tool-call compatibility evidence",
    "inspection metadata is not sufficient for full checkpoint resolution or resume",
    "content digests are not authentication authorization or truth",
    "no model process network persistence hidden-state remote or external-effect operation",
];

const SOURCE_CASES_DIGEST_DOMAIN: &str = "cantor.custody-query-surface.cases.v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyQuerySurfaceByteCase {
    pub case_ordinal: u32,
    pub checkpoint_phase: EffectlessDispatchPhase,
    pub transport_position: u32,
    pub terminal_reflection: bool,
    pub checkpoint_digest: ContentDigest,
    pub inspect_query_bytes: usize,
    pub resolve_query_bytes: usize,
    pub inspect_response_bytes: usize,
    pub resolve_response_bytes: usize,
    pub resolve_minus_inspect_response_bytes: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyQuerySurfaceMeasurement {
    pub profile: String,
    pub registry_root: ContentDigest,
    pub source_cases_digest: ContentDigest,
    pub cases: Vec<CustodyQuerySurfaceByteCase>,
    pub case_count: usize,
    pub total_inspect_query_bytes: usize,
    pub total_resolve_query_bytes: usize,
    pub total_inspect_response_bytes: usize,
    pub total_resolve_response_bytes: usize,
    pub total_resolve_minus_inspect_response_bytes: i64,
    pub minimum_inspect_response_bytes: usize,
    pub maximum_inspect_response_bytes: usize,
    pub inspect_to_resolve_response_basis_points: u64,
    pub all_inspect_responses_smaller: bool,
    pub byte_basis: String,
    pub token_measurement_claimed: bool,
    pub performance_claimed: bool,
    pub provider_compatibility_claimed: bool,
    pub semantic_equivalence_claimed: bool,
    pub persistence_claimed: bool,
    pub nonclaims: Vec<String>,
}

pub fn generate_custody_query_surface_measurement() -> Result<CustodyQuerySurfaceMeasurement, String>
{
    let measurement = expected_measurement()?;
    validate_custody_query_surface_measurement(&measurement)?;
    Ok(measurement)
}

pub fn validate_custody_query_surface_measurement(
    measurement: &CustodyQuerySurfaceMeasurement,
) -> Result<(), String> {
    if measurement.profile != CUSTODY_QUERY_SURFACE_MEASUREMENT_PROFILE
        || measurement.byte_basis != "normalized pretty UTF-8 JSON bytes with one LF"
        || measurement.token_measurement_claimed
        || measurement.performance_claimed
        || measurement.provider_compatibility_claimed
        || measurement.semantic_equivalence_claimed
        || measurement.persistence_claimed
        || measurement.nonclaims != measurement_nonclaims()
    {
        return Err("custody query surface measurement identity or claims are invalid".to_owned());
    }
    let expected = expected_measurement()?;
    if measurement != &expected {
        return Err("custody query surface measurement differs from reconstruction".to_owned());
    }
    Ok(())
}

pub fn pretty_custody_query_surface_measurement_bytes(
    measurement: &CustodyQuerySurfaceMeasurement,
) -> Result<Vec<u8>, String> {
    validate_custody_query_surface_measurement(measurement)?;
    let mut bytes = serde_json::to_vec_pretty(measurement)
        .map_err(|error| format!("custody query measurement serialization failed: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn expected_measurement() -> Result<CustodyQuerySurfaceMeasurement, String> {
    let registry = generate_scripted_checkpoint_custody_registry()?;
    validate_scripted_checkpoint_custody_registry(&registry)?;
    let corpus = generate_scripted_dispatch_resume_corpus()?;
    let mut cases = Vec::with_capacity(corpus.cases.len());
    for case in &corpus.cases {
        let handle = compile_dispatch_checkpoint_handle(
            &case.checkpoint,
            case.transport_position,
            case.terminal_reflection,
        )?;
        let inspect_query = CheckpointCustodyQuery {
            profile: CHECKPOINT_CUSTODY_QUERY_PROFILE.to_owned(),
            expected_registry_root: registry.root_digest.clone(),
            operation: CheckpointCustodyOperation::Inspect {
                handle: handle.clone(),
            },
        };
        let checkpoint_digest = handle.checkpoint_digest.clone();
        let resolve_query = CheckpointCustodyQuery {
            profile: CHECKPOINT_CUSTODY_QUERY_PROFILE.to_owned(),
            expected_registry_root: registry.root_digest.clone(),
            operation: CheckpointCustodyOperation::Resolve { handle },
        };
        let inspect_response = dispatch_checkpoint_custody_query(&registry, &inspect_query)?;
        let resolve_response = dispatch_checkpoint_custody_query(&registry, &resolve_query)?;
        let inspect_query_bytes = pretty_checkpoint_custody_query_bytes(&inspect_query)?.len();
        let resolve_query_bytes = pretty_checkpoint_custody_query_bytes(&resolve_query)?.len();
        let inspect_response_bytes =
            pretty_checkpoint_custody_response_bytes(&registry, &inspect_query, &inspect_response)?
                .len();
        let resolve_response_bytes =
            pretty_checkpoint_custody_response_bytes(&registry, &resolve_query, &resolve_response)?
                .len();
        cases.push(CustodyQuerySurfaceByteCase {
            case_ordinal: case.case_ordinal,
            checkpoint_phase: case.checkpoint_phase,
            transport_position: case.transport_position,
            terminal_reflection: case.terminal_reflection,
            checkpoint_digest,
            inspect_query_bytes,
            resolve_query_bytes,
            inspect_response_bytes,
            resolve_response_bytes,
            resolve_minus_inspect_response_bytes: signed_difference(
                resolve_response_bytes,
                inspect_response_bytes,
            )?,
        });
    }
    let total_inspect_query_bytes = sum(cases.iter().map(|case| case.inspect_query_bytes))?;
    let total_resolve_query_bytes = sum(cases.iter().map(|case| case.resolve_query_bytes))?;
    let total_inspect_response_bytes = sum(cases.iter().map(|case| case.inspect_response_bytes))?;
    let total_resolve_response_bytes = sum(cases.iter().map(|case| case.resolve_response_bytes))?;
    let minimum_inspect_response_bytes = cases
        .iter()
        .map(|case| case.inspect_response_bytes)
        .min()
        .ok_or_else(|| "custody query measurement requires cases".to_owned())?;
    let maximum_inspect_response_bytes = cases
        .iter()
        .map(|case| case.inspect_response_bytes)
        .max()
        .ok_or_else(|| "custody query measurement requires cases".to_owned())?;
    let source_cases_digest = digest_json(SOURCE_CASES_DIGEST_DOMAIN, &cases)?;
    Ok(CustodyQuerySurfaceMeasurement {
        profile: CUSTODY_QUERY_SURFACE_MEASUREMENT_PROFILE.to_owned(),
        registry_root: registry.root_digest,
        source_cases_digest,
        case_count: cases.len(),
        total_inspect_query_bytes,
        total_resolve_query_bytes,
        total_inspect_response_bytes,
        total_resolve_response_bytes,
        total_resolve_minus_inspect_response_bytes: signed_difference(
            total_resolve_response_bytes,
            total_inspect_response_bytes,
        )?,
        minimum_inspect_response_bytes,
        maximum_inspect_response_bytes,
        inspect_to_resolve_response_basis_points: basis_points(
            total_inspect_response_bytes,
            total_resolve_response_bytes,
        )?,
        all_inspect_responses_smaller: cases
            .iter()
            .all(|case| case.inspect_response_bytes < case.resolve_response_bytes),
        byte_basis: "normalized pretty UTF-8 JSON bytes with one LF".to_owned(),
        token_measurement_claimed: false,
        performance_claimed: false,
        provider_compatibility_claimed: false,
        semantic_equivalence_claimed: false,
        persistence_claimed: false,
        nonclaims: measurement_nonclaims(),
        cases,
    })
}

fn sum(mut values: impl Iterator<Item = usize>) -> Result<usize, String> {
    values.try_fold(0_usize, |total, value| {
        total
            .checked_add(value)
            .ok_or_else(|| "custody query measurement byte total overflow".to_owned())
    })
}

fn signed_difference(larger: usize, smaller: usize) -> Result<i64, String> {
    let larger = i64::try_from(larger)
        .map_err(|_| "custody query measurement byte count cannot fit i64".to_owned())?;
    let smaller = i64::try_from(smaller)
        .map_err(|_| "custody query measurement byte count cannot fit i64".to_owned())?;
    larger
        .checked_sub(smaller)
        .ok_or_else(|| "custody query measurement byte difference overflow".to_owned())
}

fn basis_points(numerator: usize, denominator: usize) -> Result<u64, String> {
    if denominator == 0 {
        return Err("custody query measurement denominator is zero".to_owned());
    }
    let numerator = u128::try_from(numerator)
        .map_err(|_| "custody query numerator cannot fit u128".to_owned())?;
    let denominator = u128::try_from(denominator)
        .map_err(|_| "custody query denominator cannot fit u128".to_owned())?;
    let rounded = numerator
        .checked_mul(10_000)
        .and_then(|value| value.checked_add(denominator / 2))
        .ok_or_else(|| "custody query ratio arithmetic overflow".to_owned())?
        / denominator;
    u64::try_from(rounded).map_err(|_| "custody query ratio cannot fit u64".to_owned())
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> Result<ContentDigest, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("custody query measurement digest failed: {error}"))?;
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

fn measurement_nonclaims() -> Vec<String> {
    CUSTODY_QUERY_SURFACE_MEASUREMENT_NONCLAIMS
        .iter()
        .map(ToString::to_string)
        .collect()
}
