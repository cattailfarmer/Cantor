use std::{collections::BTreeMap, error::Error, fmt};

use cantor_core::{
    ContentDigest, NATIVE_LIFECYCLE_CUSTODY_HANDLE_PROFILE, NativeLifecycleValidationOperation,
    new_native_lifecycle_custody_registry,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    BridgeObservation, CustodyOperation, CustodyStatus, CustodyWireResponse,
    GovernedLifecycleFixture, LifecycleFixtureCase, MAX_STRUCTURED_RESPONSE_BYTES, McpArm,
    RegistrationObservation,
};

pub const PROVIDER_INDEPENDENT_PROBE_NAME: &str = "cantor_lifecycle_bridge_probe";
pub const PROVIDER_INDEPENDENT_CONTRACT: &str =
    "Cantor_Live_Lifecycle_Tool_Loop_Measurement_P0.sop";
pub const PROVIDER_INDEPENDENT_EVIDENCE_MAX_BYTES: usize = 2_097_152;
const CUSTODY_RESPONSE_PROFILE: &str = "cantor-native-lifecycle-volatile-custody-mcp/0.1";
const CUSTODY_RESPONSE_NONCLAIMS: [&str; 6] = [
    "state is process-local and restart loses every retained request",
    "digest lookup returns retained meaning and does not reconstruct omitted meaning",
    "custody coherence is not truth correctness safety or verification passage",
    "digests are not authentication authorization signatures or permissions",
    "no client isolation persistence expiry eviction or crash recovery is claimed",
    "no provider model filesystem process network runner or external effect is accessed",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbePhase {
    FirstCall,
    SteadyState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIndependentProbeTrial {
    pub sequence: usize,
    pub phase: ProbePhase,
    pub fixture_case: LifecycleFixtureCase,
    pub observation: BridgeObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeComparison {
    pub stateless_transport_argument_bytes: usize,
    pub custody_transport_argument_bytes: usize,
    pub transport_bytes_saved: usize,
    pub custody_to_stateless_argument_basis_points: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRestartTrial {
    pub status: String,
    pub old_handle_refused: bool,
    pub response: CustodyWireResponse,
    pub excluded_from_steady_state: bool,
    pub persistence_claimed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIndependentProbeReport {
    pub probe: String,
    pub contract: String,
    pub status: String,
    pub started_unix_ms: u128,
    pub finished_unix_ms: u128,
    pub provider_contacted: bool,
    pub private_reasoning_recorded: bool,
    pub custody_registrations_outside_steady_state: Vec<RegistrationObservation>,
    pub comparison: ProbeComparison,
    pub restart_trial: ProbeRestartTrial,
    pub trials: Vec<ProviderIndependentProbeTrial>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedProbeEvidence {
    pub profile: String,
    pub status: String,
    pub source_digest: ContentDigest,
    pub source_bytes: usize,
    pub verified_trial_count: usize,
    pub first_call_trial_count: usize,
    pub steady_state_trial_count: usize,
    pub comparison: ProbeComparison,
    pub provider_contacted: bool,
    pub private_reasoning_recorded: bool,
    pub restart_old_handle_refused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceVerificationFault {
    pub field: String,
    pub detail: String,
}

impl EvidenceVerificationFault {
    fn new(field: impl Into<String>, detail: impl fmt::Display) -> Self {
        Self {
            field: field.into(),
            detail: detail.to_string().chars().take(1_000).collect(),
        }
    }
}

impl fmt::Display for EvidenceVerificationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.detail)
    }
}

impl Error for EvidenceVerificationFault {}

pub fn verify_provider_independent_probe(
    source: &[u8],
) -> Result<VerifiedProbeEvidence, EvidenceVerificationFault> {
    ensure(
        "source_bytes",
        !source.is_empty() && source.len() <= PROVIDER_INDEPENDENT_EVIDENCE_MAX_BYTES,
        format!(
            "must be 1..={PROVIDER_INDEPENDENT_EVIDENCE_MAX_BYTES}; observed {}",
            source.len()
        ),
    )?;
    let report: ProviderIndependentProbeReport = serde_json::from_slice(source)
        .map_err(|error| EvidenceVerificationFault::new("source_json", error))?;
    ensure_equal(
        "probe",
        report.probe.as_str(),
        PROVIDER_INDEPENDENT_PROBE_NAME,
    )?;
    ensure_equal(
        "contract",
        report.contract.as_str(),
        PROVIDER_INDEPENDENT_CONTRACT,
    )?;
    ensure_equal("status", report.status.as_str(), "passed")?;
    ensure(
        "time_interval",
        report.finished_unix_ms >= report.started_unix_ms,
        "finished_unix_ms precedes started_unix_ms",
    )?;
    ensure_equal("provider_contacted", report.provider_contacted, false)?;
    ensure_equal(
        "private_reasoning_recorded",
        report.private_reasoning_recorded,
        false,
    )?;

    let fixtures = BTreeMap::from([
        (
            LifecycleFixtureCase::Valid,
            GovernedLifecycleFixture::load(LifecycleFixtureCase::Valid)
                .map_err(|error| EvidenceVerificationFault::new("valid_fixture", error))?,
        ),
        (
            LifecycleFixtureCase::LifecycleRefused,
            GovernedLifecycleFixture::load(LifecycleFixtureCase::LifecycleRefused)
                .map_err(|error| EvidenceVerificationFault::new("refused_fixture", error))?,
        ),
    ]);
    let registrations = verify_registrations(
        &report.custody_registrations_outside_steady_state,
        &fixtures,
    )?;
    verify_trials(&report.trials, &fixtures, &registrations)?;
    verify_restart(&report.restart_trial)?;

    let stateless_bytes = transport_argument_bytes(&report.trials, McpArm::Stateless);
    let custody_bytes = transport_argument_bytes(&report.trials, McpArm::VolatileCustody);
    let recomputed = ProbeComparison {
        stateless_transport_argument_bytes: stateless_bytes,
        custody_transport_argument_bytes: custody_bytes,
        transport_bytes_saved: stateless_bytes.saturating_sub(custody_bytes),
        custody_to_stateless_argument_basis_points: custody_bytes
            .saturating_mul(10_000)
            .checked_div(stateless_bytes)
            .unwrap_or(0),
    };
    ensure_equal("comparison", report.comparison, recomputed)?;

    Ok(VerifiedProbeEvidence {
        profile: "cantor-lifecycle-provider-independent-evidence-verification/0.1".to_owned(),
        status: "passed".to_owned(),
        source_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: sha256_hex(source),
        },
        source_bytes: source.len(),
        verified_trial_count: report.trials.len(),
        first_call_trial_count: report
            .trials
            .iter()
            .filter(|trial| trial.phase == ProbePhase::FirstCall)
            .count(),
        steady_state_trial_count: report
            .trials
            .iter()
            .filter(|trial| trial.phase == ProbePhase::SteadyState)
            .count(),
        comparison: recomputed,
        provider_contacted: false,
        private_reasoning_recorded: false,
        restart_old_handle_refused: true,
    })
}

fn verify_registrations<'a>(
    observations: &'a [RegistrationObservation],
    fixtures: &BTreeMap<LifecycleFixtureCase, GovernedLifecycleFixture>,
) -> Result<BTreeMap<LifecycleFixtureCase, &'a RegistrationObservation>, EvidenceVerificationFault>
{
    ensure_equal("registration_count", observations.len(), fixtures.len())?;
    let mut registrations = BTreeMap::new();
    for observation in observations {
        let (case, fixture) = fixtures
            .iter()
            .find(|(_, fixture)| fixture.fixture_id == observation.fixture_id)
            .ok_or_else(|| {
                EvidenceVerificationFault::new("registration_fixture_id", &observation.fixture_id)
            })?;
        ensure(
            "duplicate_registration",
            registrations.insert(*case, observation).is_none(),
            &observation.fixture_id,
        )?;
        let expected_argument_bytes = encoded_len(&json!({
            "command": {"operation": "register", "request": fixture.request.clone()}
        }))?;
        ensure_equal(
            "registration_argument_bytes",
            observation.argument_bytes,
            expected_argument_bytes,
        )?;
        ensure_response_bound(
            "registration_structured_response_bytes",
            observation.structured_response_bytes,
        )?;
        ensure_equal(
            "registration_handle_profile",
            observation.handle.profile.as_str(),
            NATIVE_LIFECYCLE_CUSTODY_HANDLE_PROFILE,
        )?;
        ensure_equal(
            "registration_handle_operation",
            &observation.handle.operation,
            &NativeLifecycleValidationOperation::ValidateArtifact,
        )?;
        ensure_equal(
            "registration_handle_request_id",
            &observation.handle.request_id,
            &fixture.request.request_id,
        )?;
        ensure_equal(
            "registration_handle_request_digest",
            &observation.handle.request_digest,
            &ContentDigest {
                algorithm: "sha256".to_owned(),
                value: sha256_hex(fixture.request_bytes),
            },
        )?;
    }
    Ok(registrations)
}

fn verify_trials(
    trials: &[ProviderIndependentProbeTrial],
    fixtures: &BTreeMap<LifecycleFixtureCase, GovernedLifecycleFixture>,
    registrations: &BTreeMap<LifecycleFixtureCase, &RegistrationObservation>,
) -> Result<(), EvidenceVerificationFault> {
    let expected = [
        (
            ProbePhase::FirstCall,
            LifecycleFixtureCase::Valid,
            McpArm::Stateless,
        ),
        (
            ProbePhase::FirstCall,
            LifecycleFixtureCase::Valid,
            McpArm::VolatileCustody,
        ),
        (
            ProbePhase::FirstCall,
            LifecycleFixtureCase::LifecycleRefused,
            McpArm::Stateless,
        ),
        (
            ProbePhase::FirstCall,
            LifecycleFixtureCase::LifecycleRefused,
            McpArm::VolatileCustody,
        ),
        (
            ProbePhase::SteadyState,
            LifecycleFixtureCase::Valid,
            McpArm::Stateless,
        ),
        (
            ProbePhase::SteadyState,
            LifecycleFixtureCase::Valid,
            McpArm::VolatileCustody,
        ),
        (
            ProbePhase::SteadyState,
            LifecycleFixtureCase::LifecycleRefused,
            McpArm::Stateless,
        ),
        (
            ProbePhase::SteadyState,
            LifecycleFixtureCase::LifecycleRefused,
            McpArm::VolatileCustody,
        ),
    ];
    ensure_equal("trial_count", trials.len(), expected.len())?;
    for (sequence, (trial, expected_coordinate)) in trials.iter().zip(expected).enumerate() {
        ensure_equal("trial_sequence", trial.sequence, sequence)?;
        ensure_equal(
            "trial_coordinate",
            (trial.phase, trial.fixture_case, trial.observation.arm),
            expected_coordinate,
        )?;
        let fixture = fixtures.get(&trial.fixture_case).ok_or_else(|| {
            EvidenceVerificationFault::new("trial_fixture_case", "fixture is unavailable")
        })?;
        ensure_equal(
            "trial_fixture_id",
            trial.observation.fixture_id.as_str(),
            fixture.fixture_id,
        )?;
        ensure_equal(
            "trial_exact_direct_response",
            trial.observation.exact_direct_response,
            true,
        )?;
        ensure_equal(
            "trial_lifecycle_response",
            &trial.observation.lifecycle_response,
            &fixture.direct_response,
        )?;
        ensure_equal(
            "trial_mcp_is_error",
            trial.observation.mcp_is_error,
            trial.fixture_case == LifecycleFixtureCase::LifecycleRefused,
        )?;
        ensure_response_bound(
            "trial_structured_response_bytes",
            trial.observation.structured_response_bytes,
        )?;
        let expected_argument_bytes = match trial.observation.arm {
            McpArm::Stateless => encoded_len(&json!({
                "request": fixture.request.clone()
            }))?,
            McpArm::VolatileCustody => {
                let registration = registrations.get(&trial.fixture_case).ok_or_else(|| {
                    EvidenceVerificationFault::new(
                        "trial_registration",
                        "matching custody handle is unavailable",
                    )
                })?;
                encoded_len(&json!({
                    "command": {"operation": "validate", "handle": registration.handle.clone()}
                }))?
            }
        };
        ensure_equal(
            "trial_argument_bytes",
            trial.observation.argument_bytes,
            expected_argument_bytes,
        )?;
    }
    Ok(())
}

fn verify_restart(restart: &ProbeRestartTrial) -> Result<(), EvidenceVerificationFault> {
    ensure_equal("restart_status", restart.status.as_str(), "passed")?;
    ensure_equal(
        "restart_old_handle_refused",
        restart.old_handle_refused,
        true,
    )?;
    ensure_equal(
        "restart_excluded_from_steady_state",
        restart.excluded_from_steady_state,
        true,
    )?;
    ensure_equal(
        "restart_persistence_claimed",
        restart.persistence_claimed,
        false,
    )?;
    ensure_equal(
        "restart_response_profile",
        restart.response.profile.as_str(),
        CUSTODY_RESPONSE_PROFILE,
    )?;
    ensure_equal(
        "restart_response_operation",
        restart.response.operation,
        CustodyOperation::Validate,
    )?;
    ensure_equal(
        "restart_response_status",
        restart.response.status,
        CustodyStatus::Refused,
    )?;
    ensure_equal("restart_response_handle", &restart.response.handle, &None)?;
    ensure_equal(
        "restart_response_lifecycle",
        &restart.response.lifecycle_response,
        &None,
    )?;
    let fault = restart
        .response
        .fault
        .as_ref()
        .ok_or_else(|| EvidenceVerificationFault::new("restart_response_fault", "missing"))?;
    ensure_equal(
        "restart_response_fault_code",
        fault.code.as_str(),
        "handle_refused",
    )?;
    let registry =
        restart.response.registry.as_ref().ok_or_else(|| {
            EvidenceVerificationFault::new("restart_response_registry", "missing")
        })?;
    let empty_registry = new_native_lifecycle_custody_registry()
        .map_err(|error| EvidenceVerificationFault::new("empty_registry", error))?;
    ensure_equal(
        "restart_registry_profile",
        &registry.profile,
        &empty_registry.profile,
    )?;
    ensure_equal("restart_registry_entry_count", registry.entry_count, 0)?;
    ensure_equal(
        "restart_registry_retained_request_bytes",
        registry.retained_request_bytes,
        0,
    )?;
    ensure_equal(
        "restart_registry_root_digest",
        &registry.root_digest,
        &empty_registry.root_digest,
    )?;
    let expected_nonclaims = CUSTODY_RESPONSE_NONCLAIMS.map(str::to_owned).to_vec();
    ensure_equal(
        "restart_response_nonclaims",
        &restart.response.nonclaims,
        &expected_nonclaims,
    )?;
    Ok(())
}

fn transport_argument_bytes(trials: &[ProviderIndependentProbeTrial], arm: McpArm) -> usize {
    trials
        .iter()
        .filter(|trial| trial.observation.arm == arm)
        .map(|trial| trial.observation.argument_bytes)
        .sum()
}

fn encoded_len(value: &serde_json::Value) -> Result<usize, EvidenceVerificationFault> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|error| EvidenceVerificationFault::new("canonical_json", error))
}

fn ensure_response_bound(field: &str, observed: usize) -> Result<(), EvidenceVerificationFault> {
    ensure(
        field,
        observed > 0 && observed <= MAX_STRUCTURED_RESPONSE_BYTES,
        format!("must be 1..={MAX_STRUCTURED_RESPONSE_BYTES}; observed {observed}"),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ensure(
    field: &str,
    condition: bool,
    detail: impl fmt::Display,
) -> Result<(), EvidenceVerificationFault> {
    if condition {
        Ok(())
    } else {
        Err(EvidenceVerificationFault::new(field, detail))
    }
}

fn ensure_equal<T>(field: &str, observed: T, expected: T) -> Result<(), EvidenceVerificationFault>
where
    T: PartialEq + fmt::Debug,
{
    ensure(
        field,
        observed == expected,
        format!("expected {expected:?}; observed {observed:?}"),
    )
}
