//! Governed production-broker authority and state forms for C-drive B1 P1.
//!
//! The published formation authorizes this implementation but not a physical
//! activation. The activation seal is deliberately absent, so no public call
//! can construct the crate-private execution permit or reach the Windows
//! contained-child backend.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Number, Value};

use crate::{
    B1CDrivePreflightProducerChildKind, B1CDrivePreflightProducerPlan,
    B1CDrivePreflightProducerPlanRequest, from_b1_cdrive_preflight_producer_plan_machine_form,
    from_b1_cdrive_preflight_producer_plan_request_machine_form,
    validate_b1_cdrive_preflight_producer_plan,
};

pub const B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_REQUEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-broker-implementation-request/0.1";
pub const B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_RECEIPT_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-broker-implementation-receipt/0.1";
pub const B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_STATUS: &str =
    "production_broker_implemented_physical_run_not_authorized";
pub const B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_AUTHORITY: &str =
    "bounded_implementation_only";
pub const B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID: &str =
    "d4788c6a-7e02-4866-8729-d4cf76e94259";
pub const B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID: &str = "0fb58a71-348c-4df3-83bc-33989c826f26";
pub const B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID: &str = "5970337b-0f81-4438-86a0-afb0b9b82d39";
pub const B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT: &str =
    "4093fa9e8eb67a157bea367363721ee8bf507837";
pub const B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND: &str =
    "2a0514616f66dcaf9bd845927ddbd547b25b53b7";
pub const B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES: usize = 2 * 1024 * 1024;
pub const B1_CDRIVE_PRODUCTION_BROKER_FIXTURE_INPUT_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-broker-fixture-input/0.1";
pub const B1_CDRIVE_PRODUCTION_BROKER_FIXTURE_OUTCOME_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-broker-fixture-outcome/0.1";
pub const B1_CDRIVE_PRODUCTION_COMMISSION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-commission/0.1";
pub const B1_CDRIVE_PRODUCTION_OPERATOR_AUTHORIZATION_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-operator-authorization/0.1";
pub const B1_CDRIVE_PRODUCTION_PREPARED_RECEIPT_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-production-broker-prepared-receipt/0.1";

const REQUEST_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-broker-implementation-request.v1";
const RECEIPT_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-broker-implementation-receipt.v1";
const AUTHORITY_RECORD_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-broker-authority-record.v1";
const AUTHORITY_JOIN_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-broker-authority-join.v1";
const COMMISSION_DOMAIN: &str = "cantor.self-work-update-broker.b1.cdrive-production-commission.v1";
const AUTHORIZATION_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-operator-authorization.v1";
const PREPARED_RECEIPT_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-prepared-receipt.v1";
const OBSERVATION_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-observation.v1";
const LEDGER_DOMAIN: &str = "cantor.self-work-update-broker.b1.cdrive-production-ledger.v1";
const FIXTURE_INPUT_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-fixture-input.v1";
const FIXTURE_OUTCOME_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-production-fixture-outcome.v1";
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 256;
const EXPECTED_DIRECT_CHILD_COUNT: u8 = 4;
const EXPECTED_AGGREGATE_JOB_PROCESS_MAXIMUM: u8 = 7;
const EXPECTED_ENVIRONMENT_NAME_COUNT: u8 = 7;
const EXPECTED_DENIED_ENVIRONMENT_NAME_COUNT: u8 = 16;
const EXPECTED_OUTBOUND_FRAME_COUNT: u8 = 6;
const EXPECTED_INCOMING_FRAME_COUNT: u8 = 6;
const EXPECTED_TOTAL_FRAME_COUNT: u8 = 12;
const PHYSICAL_ACTIVATION_DIGEST: Option<&str> = None;

const REQUIRED_AUTHORITIES: [&str; 5] = [
    "authenticated_external_commission",
    "continuous_exclusive_lease",
    "durable_consumption_claim",
    "production_broker_prepared_receipt",
    "fresh_phase3a_replay",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionBrokerAuthorityClass {
    AuthenticatedExternalCommission,
    ContinuousExclusiveLease,
    DurableConsumptionClaim,
    ProductionBrokerPreparedReceipt,
    FreshPhase3aReplay,
}

impl B1CDriveProductionBrokerAuthorityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedExternalCommission => "authenticated_external_commission",
            Self::ContinuousExclusiveLease => "continuous_exclusive_lease",
            Self::DurableConsumptionClaim => "durable_consumption_claim",
            Self::ProductionBrokerPreparedReceipt => "production_broker_prepared_receipt",
            Self::FreshPhase3aReplay => "fresh_phase3a_replay",
        }
    }
}

pub fn required_b1_cdrive_production_broker_authority_classes()
-> [B1CDriveProductionBrokerAuthorityClass; 5] {
    use B1CDriveProductionBrokerAuthorityClass as Class;
    [
        Class::AuthenticatedExternalCommission,
        Class::ContinuousExclusiveLease,
        Class::DurableConsumptionClaim,
        Class::ProductionBrokerPreparedReceipt,
        Class::FreshPhase3aReplay,
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerAuthorityRecord {
    pub class: B1CDriveProductionBrokerAuthorityClass,
    pub artifact_profile: String,
    pub artifact_sha256: ContentDigest,
    pub externally_authenticated: bool,
    pub fixture_only: bool,
    pub record_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerFiveAuthorityJoin {
    pub records: Vec<B1CDriveProductionBrokerAuthorityRecord>,
    pub join_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionCommission {
    pub profile: String,
    pub issuer: String,
    pub subject: String,
    pub recovery_owner: String,
    pub attempt_uuid: String,
    pub conversation_uuid: String,
    pub purpose: String,
    pub implementation_commit: String,
    pub implementation_bookend: String,
    pub expected_current_commit: String,
    pub plan_sha256: ContentDigest,
    pub prepared_receipt_sha256: ContentDigest,
    pub phase3a_sha256: ContentDigest,
    pub operator_authorization_sha256: ContentDigest,
    pub issued_at_unix_millis: u64,
    pub expires_at_unix_millis: u64,
    pub maximum_attempts: u8,
    pub retry_count: u8,
    pub broker_authored: bool,
    pub fixture_only: bool,
    pub commission_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionOperatorAuthorization {
    pub profile: String,
    pub issuer: String,
    pub subject: String,
    pub role: String,
    pub attempt_uuid: String,
    pub conversation_uuid: String,
    pub purpose: String,
    pub plan_sha256: ContentDigest,
    pub issued_at_unix_millis: u64,
    pub expires_at_unix_millis: u64,
    pub broker_authored: bool,
    pub fixture_only: bool,
    pub authorization_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerPreparedReceipt {
    pub profile: String,
    pub scratch_root: String,
    pub candidate_root: String,
    pub evidence_root: String,
    pub lease_path: String,
    pub ledger_path: String,
    pub plan_sha256: ContentDigest,
    pub phase3a_sha256: ContentDigest,
    pub unclaimed_ledger_sha256: ContentDigest,
    pub fixed_ledger_bytes: u32,
    pub lease_preexisting_regular_nonlink: bool,
    pub ledger_preexisting_regular_nonlink: bool,
    pub evidence_preexisting_directory_nonlink: bool,
    pub fixture_only: bool,
    pub prepared_receipt_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerMutableObservation {
    pub sequence: u8,
    pub expected_current_commit: String,
    pub free_bytes: u64,
    pub minimum_free_bytes: u64,
    pub reserved_root_present: bool,
    pub reserved_ref_present: bool,
    pub candidate_clean: bool,
    pub sentinels_exact: bool,
    pub write_canary_absent: bool,
    pub executable_exact: bool,
    pub prepared_receipt_sha256: ContentDigest,
    pub phase3a_sha256: ContentDigest,
    pub plan_sha256: ContentDigest,
    pub broker_process_count: u32,
    pub observed_state_sha256: ContentDigest,
    pub observation_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionBrokerLedgerState {
    Unclaimed,
    Claimed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerLedgerFixture {
    pub prior_state: B1CDriveProductionBrokerLedgerState,
    pub fixed_ledger_bytes: u32,
    pub prior_bytes_sha256: ContentDigest,
    pub claimed_bytes_sha256: ContentDigest,
    pub flush_succeeded: bool,
    pub close_reopen_succeeded: bool,
    pub byte_verification_succeeded: bool,
    pub fixture_only: bool,
    pub ledger_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionBrokerFixtureFaultPoint {
    BeforeLease,
    AfterLease,
    AfterReobserve,
    AfterClaim,
    AfterTestCapability,
    DuringChildren,
    AfterEvidenceRetention,
    AfterCommissionConsumption,
    AfterLeaseRelease,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerFixtureInput {
    pub profile: String,
    pub implementation_request_machine_form: String,
    pub authorities: B1CDriveProductionBrokerFiveAuthorityJoin,
    pub commission: B1CDriveProductionCommission,
    pub operator_authorization: B1CDriveProductionOperatorAuthorization,
    pub prepared_receipt: B1CDriveProductionBrokerPreparedReceipt,
    pub first_observation: B1CDriveProductionBrokerMutableObservation,
    pub second_observation: B1CDriveProductionBrokerMutableObservation,
    pub ledger: B1CDriveProductionBrokerLedgerFixture,
    pub fault_point: Option<B1CDriveProductionBrokerFixtureFaultPoint>,
    pub input_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerEffectAccount {
    pub physical_contact: bool,
    pub process_creation_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub network_contact_count: u32,
    pub writer_run_count: u32,
    pub git_mutation_count: u32,
    pub publication_count: u32,
    pub persistence_count: u32,
    pub activation_count: u32,
    pub d_drive_contact_count: u32,
    pub remote_contact_count: u32,
    pub fpga_contact_count: u32,
    pub minecraft_contact_count: u32,
    pub wsl_compile_count: u32,
    pub cleanup_count: u32,
    pub foreign_effect_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerFixtureOutcome {
    pub profile: String,
    pub terminal_state: B1CDriveProductionBrokerState,
    pub transitions: Vec<B1CDriveProductionBrokerTransition>,
    pub call_ledger: Vec<String>,
    pub lease_held_at_terminal: bool,
    pub ledger_claimed: bool,
    pub evidence_retained: bool,
    pub commission_consumed: bool,
    pub may_have_mutated: bool,
    pub private_execution_permit_constructed: bool,
    pub fake_execution_capability_consumed: bool,
    pub windows_backend_invoked: bool,
    pub retry_count: u8,
    pub cleanup_count: u8,
    pub effect_account: B1CDriveProductionBrokerEffectAccount,
    pub outcome_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerImplementationRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub producer_plan_request_machine_form: String,
    pub producer_plan_machine_form: String,
    pub physical_activation_digest: Option<String>,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionBrokerState {
    InputsValidated,
    LeaseHeld,
    StateReobserved,
    ConsumptionClaimed,
    PermitIssued,
    ChildrenRunning,
    EvidenceRetained,
    CommissionConsumed,
    LeaseReleased,
    Complete,
    NotRun,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerTransition {
    pub sequence: u8,
    pub from: B1CDriveProductionBrokerState,
    pub to: B1CDriveProductionBrokerState,
    pub consumption_claimed_after: bool,
    pub process_creation_allowed_after: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerImplementationReceipt {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub request_sha256: ContentDigest,
    pub producer_plan_sha256: ContentDigest,
    pub required_authorities: Vec<String>,
    pub success_transitions: Vec<B1CDriveProductionBrokerTransition>,
    pub direct_child_count: u8,
    pub aggregate_job_process_maximum: u8,
    pub environment_name_count: u8,
    pub denied_environment_name_count: u8,
    pub outbound_frame_count: u8,
    pub incoming_frame_count: u8,
    pub total_transcript_frame_count: u8,
    pub physical_activation_digest_configured: bool,
    pub private_execution_permit_constructed: bool,
    pub windows_backend_invoked: bool,
    pub commission_issued: bool,
    pub authorization_authenticated: bool,
    pub broker_preparation_run: bool,
    pub exclusive_lease_acquired: bool,
    pub consumption_ledger_claimed: bool,
    pub production_broker_run: bool,
    pub physical_contact: bool,
    pub child_process_count: u32,
    pub provider_trial_count: u32,
    pub model_turn_count: u32,
    pub mcp_call_count: u32,
    pub network_contact_count: u32,
    pub git_mutation_count: u32,
    pub d_drive_contact_count: u32,
    pub wsl_compile_count: u32,
    pub cleanup_count: u32,
    pub receipt_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDriveProductionBrokerFaultCode {
    Bound,
    Digest,
    Lineage,
    MachineForm,
    ProducerPlan,
    Authority,
    Commission,
    Lease,
    Ledger,
    Observation,
    Evidence,
    Activation,
    Containment,
    State,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerFault {
    pub code: B1CDriveProductionBrokerFaultCode,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveWindowsContainedChildSpec {
    pub attempt_sha256: ContentDigest,
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment: Vec<(String, String)>,
    pub stdin: Vec<u8>,
    pub maximum_stdout_bytes: usize,
    pub maximum_stderr_bytes: usize,
    pub timeout_millis: u32,
    pub maximum_active_processes: u32,
    pub maximum_total_processes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDriveWindowsContainedChildObservation {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_observed_bytes: u64,
    pub stderr_observed_bytes: u64,
    pub stdout_over_bound: bool,
    pub stderr_over_bound: bool,
    pub forced_termination: bool,
    pub total_processes: u32,
    pub active_processes_at_terminal: u32,
    pub resume_previous_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerChildAccount {
    pub sequence: u8,
    pub kind: B1CDrivePreflightProducerChildKind,
    pub job_created_before_process: bool,
    pub kill_on_close: bool,
    pub breakaway_enabled: bool,
    pub inherited_handle_count: u8,
    pub process_created_suspended: bool,
    pub assigned_before_resume: bool,
    pub resume_previous_count: u32,
    pub maximum_active_processes: u32,
    pub total_processes: u32,
    pub active_processes_at_terminal: u32,
    pub late_output: bool,
    pub stdout_over_bound: bool,
    pub stderr_over_bound: bool,
    pub timed_out: bool,
    pub forced_termination: bool,
    pub exit_code: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDriveProductionBrokerTranscriptAccount {
    pub frames: Vec<Value>,
    pub allowed_read_exit_code: i64,
    pub allowed_read_stdout: String,
    pub allowed_read_stderr: String,
    pub denied_read_exit_code: i64,
    pub denied_read_stdout: String,
    pub denied_read_stderr: String,
    pub denied_write_exit_code: i64,
    pub denied_write_stdout: String,
    pub denied_write_stderr: String,
    pub denied_sentinel_disclosed: bool,
    pub write_sentinel_disclosed: bool,
    pub write_canary_present: bool,
}

impl fmt::Display for B1CDriveProductionBrokerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1CDriveProductionBrokerFault {}

/// Crate-private, non-serializable, non-clone execution capability.
///
/// There is intentionally no production constructor while the compile-time
/// activation digest is absent. The Windows backend requires this type.
pub(crate) struct B1CDrivePhysicalExecutionPermit {
    attempt_sha256: ContentDigest,
}

impl B1CDrivePhysicalExecutionPermit {
    pub(crate) fn attempt_sha256(&self) -> &ContentDigest {
        &self.attempt_sha256
    }
}

pub fn compile_b1_cdrive_production_broker_implementation_receipt(
    request: &B1CDriveProductionBrokerImplementationRequest,
) -> Result<B1CDriveProductionBrokerImplementationReceipt, B1CDriveProductionBrokerFault> {
    let plan = validate_request(request)?;
    let mut receipt = B1CDriveProductionBrokerImplementationReceipt {
        profile: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_RECEIPT_PROFILE.to_owned(),
        status: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_STATUS.to_owned(),
        authority: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_AUTHORITY.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT.to_owned(),
        formation_bookend: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND.to_owned(),
        request_sha256: request.request_sha256.clone(),
        producer_plan_sha256: plan.plan_sha256,
        required_authorities: REQUIRED_AUTHORITIES.map(str::to_owned).to_vec(),
        success_transitions: canonical_b1_cdrive_production_broker_success_transitions(),
        direct_child_count: EXPECTED_DIRECT_CHILD_COUNT,
        aggregate_job_process_maximum: EXPECTED_AGGREGATE_JOB_PROCESS_MAXIMUM,
        environment_name_count: EXPECTED_ENVIRONMENT_NAME_COUNT,
        denied_environment_name_count: EXPECTED_DENIED_ENVIRONMENT_NAME_COUNT,
        outbound_frame_count: EXPECTED_OUTBOUND_FRAME_COUNT,
        incoming_frame_count: EXPECTED_INCOMING_FRAME_COUNT,
        total_transcript_frame_count: EXPECTED_TOTAL_FRAME_COUNT,
        physical_activation_digest_configured: PHYSICAL_ACTIVATION_DIGEST.is_some(),
        private_execution_permit_constructed: false,
        windows_backend_invoked: false,
        commission_issued: false,
        authorization_authenticated: false,
        broker_preparation_run: false,
        exclusive_lease_acquired: false,
        consumption_ledger_claimed: false,
        production_broker_run: false,
        physical_contact: false,
        child_process_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        network_contact_count: 0,
        git_mutation_count: 0,
        d_drive_contact_count: 0,
        wsl_compile_count: 0,
        cleanup_count: 0,
        receipt_sha256: empty_digest(),
    };
    receipt.receipt_sha256 = b1_cdrive_production_broker_implementation_receipt_digest(&receipt)?;
    validate_b1_cdrive_production_broker_implementation_receipt(request, &receipt)?;
    Ok(receipt)
}

pub fn validate_b1_cdrive_production_broker_implementation_receipt(
    request: &B1CDriveProductionBrokerImplementationRequest,
    receipt: &B1CDriveProductionBrokerImplementationReceipt,
) -> Result<(), B1CDriveProductionBrokerFault> {
    let expected = compile_receipt_without_recursive_validation(request)?;
    if &expected != receipt {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::MachineForm,
            "production-broker implementation receipt differs",
        ));
    }
    Ok(())
}

fn compile_receipt_without_recursive_validation(
    request: &B1CDriveProductionBrokerImplementationRequest,
) -> Result<B1CDriveProductionBrokerImplementationReceipt, B1CDriveProductionBrokerFault> {
    let plan = validate_request(request)?;
    let mut receipt = B1CDriveProductionBrokerImplementationReceipt {
        profile: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_RECEIPT_PROFILE.to_owned(),
        status: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_STATUS.to_owned(),
        authority: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_AUTHORITY.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT.to_owned(),
        formation_bookend: B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND.to_owned(),
        request_sha256: request.request_sha256.clone(),
        producer_plan_sha256: plan.plan_sha256,
        required_authorities: REQUIRED_AUTHORITIES.map(str::to_owned).to_vec(),
        success_transitions: canonical_b1_cdrive_production_broker_success_transitions(),
        direct_child_count: EXPECTED_DIRECT_CHILD_COUNT,
        aggregate_job_process_maximum: EXPECTED_AGGREGATE_JOB_PROCESS_MAXIMUM,
        environment_name_count: EXPECTED_ENVIRONMENT_NAME_COUNT,
        denied_environment_name_count: EXPECTED_DENIED_ENVIRONMENT_NAME_COUNT,
        outbound_frame_count: EXPECTED_OUTBOUND_FRAME_COUNT,
        incoming_frame_count: EXPECTED_INCOMING_FRAME_COUNT,
        total_transcript_frame_count: EXPECTED_TOTAL_FRAME_COUNT,
        physical_activation_digest_configured: false,
        private_execution_permit_constructed: false,
        windows_backend_invoked: false,
        commission_issued: false,
        authorization_authenticated: false,
        broker_preparation_run: false,
        exclusive_lease_acquired: false,
        consumption_ledger_claimed: false,
        production_broker_run: false,
        physical_contact: false,
        child_process_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        network_contact_count: 0,
        git_mutation_count: 0,
        d_drive_contact_count: 0,
        wsl_compile_count: 0,
        cleanup_count: 0,
        receipt_sha256: empty_digest(),
    };
    receipt.receipt_sha256 = b1_cdrive_production_broker_implementation_receipt_digest(&receipt)?;
    Ok(receipt)
}

pub fn canonical_b1_cdrive_production_broker_success_transitions()
-> Vec<B1CDriveProductionBrokerTransition> {
    use B1CDriveProductionBrokerState as State;
    [
        (State::InputsValidated, State::LeaseHeld, false, false),
        (State::LeaseHeld, State::StateReobserved, false, false),
        (
            State::StateReobserved,
            State::ConsumptionClaimed,
            true,
            false,
        ),
        (State::ConsumptionClaimed, State::PermitIssued, true, true),
        (State::PermitIssued, State::ChildrenRunning, true, true),
        (State::ChildrenRunning, State::EvidenceRetained, true, false),
        (
            State::EvidenceRetained,
            State::CommissionConsumed,
            true,
            false,
        ),
        (State::CommissionConsumed, State::LeaseReleased, true, false),
        (State::LeaseReleased, State::Complete, true, false),
    ]
    .into_iter()
    .enumerate()
    .map(
        |(index, (from, to, consumption_claimed_after, process_creation_allowed_after))| {
            B1CDriveProductionBrokerTransition {
                sequence: (index + 1) as u8,
                from,
                to,
                consumption_claimed_after,
                process_creation_allowed_after,
            }
        },
    )
    .collect()
}

pub fn validate_b1_cdrive_production_broker_transition_trace(
    transitions: &[B1CDriveProductionBrokerTransition],
) -> Result<(), B1CDriveProductionBrokerFault> {
    let canonical = canonical_b1_cdrive_production_broker_success_transitions();
    if transitions == canonical {
        return Ok(());
    }
    if transitions.is_empty() {
        return Err(state_fault("transition trace is empty"));
    }
    let mut expected_state = B1CDriveProductionBrokerState::InputsValidated;
    let mut claimed = false;
    for (index, transition) in transitions.iter().enumerate() {
        if transition.sequence != (index + 1) as u8 || transition.from != expected_state {
            return Err(state_fault("transition sequence or predecessor differs"));
        }
        let terminal = matches!(
            transition.to,
            B1CDriveProductionBrokerState::NotRun
                | B1CDriveProductionBrokerState::Quarantined
                | B1CDriveProductionBrokerState::Complete
        );
        if terminal {
            if index + 1 != transitions.len()
                || transition.to != b1_cdrive_production_broker_failure_terminal(expected_state)
                || transition.consumption_claimed_after != claimed
                || transition.process_creation_allowed_after
            {
                return Err(state_fault("terminal failure truth differs"));
            }
            return Ok(());
        }
        let expected_transition = canonical
            .get(index)
            .ok_or_else(|| state_fault("transition trace exceeds canonical state machine"))?;
        if transition != expected_transition {
            return Err(state_fault("nonterminal state transition differs"));
        }
        claimed = transition.consumption_claimed_after;
        expected_state = transition.to;
    }
    Err(state_fault("transition trace is nonterminal"))
}

pub fn b1_cdrive_production_broker_failure_terminal(
    state: B1CDriveProductionBrokerState,
) -> B1CDriveProductionBrokerState {
    match state {
        B1CDriveProductionBrokerState::InputsValidated
        | B1CDriveProductionBrokerState::LeaseHeld
        | B1CDriveProductionBrokerState::StateReobserved => B1CDriveProductionBrokerState::NotRun,
        _ => B1CDriveProductionBrokerState::Quarantined,
    }
}

pub fn b1_cdrive_production_broker_authority_record_digest(
    record: &B1CDriveProductionBrokerAuthorityRecord,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = record.clone();
    normalized.record_sha256 = empty_digest();
    domain_digest(AUTHORITY_RECORD_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_broker_authority_join_digest(
    join: &B1CDriveProductionBrokerFiveAuthorityJoin,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = join.clone();
    normalized.join_sha256 = empty_digest();
    domain_digest(AUTHORITY_JOIN_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_commission_digest(
    commission: &B1CDriveProductionCommission,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = commission.clone();
    normalized.commission_sha256 = empty_digest();
    domain_digest(COMMISSION_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_operator_authorization_digest(
    authorization: &B1CDriveProductionOperatorAuthorization,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = authorization.clone();
    normalized.authorization_sha256 = empty_digest();
    domain_digest(AUTHORIZATION_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_prepared_receipt_digest(
    receipt: &B1CDriveProductionBrokerPreparedReceipt,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = receipt.clone();
    normalized.prepared_receipt_sha256 = empty_digest();
    domain_digest(PREPARED_RECEIPT_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_observed_state_digest(
    observation: &B1CDriveProductionBrokerMutableObservation,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = observation.clone();
    normalized.sequence = 0;
    normalized.observed_state_sha256 = empty_digest();
    normalized.observation_sha256 = empty_digest();
    domain_digest(
        "cantor.self-work-update-broker.b1.cdrive-production-observed-state.v1",
        &normalized,
    )
}

pub fn b1_cdrive_production_observation_digest(
    observation: &B1CDriveProductionBrokerMutableObservation,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = observation.clone();
    normalized.observation_sha256 = empty_digest();
    domain_digest(OBSERVATION_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_ledger_fixture_digest(
    ledger: &B1CDriveProductionBrokerLedgerFixture,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = ledger.clone();
    normalized.ledger_sha256 = empty_digest();
    domain_digest(LEDGER_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_broker_fixture_input_digest(
    input: &B1CDriveProductionBrokerFixtureInput,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = input.clone();
    normalized.input_sha256 = empty_digest();
    domain_digest(FIXTURE_INPUT_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_broker_fixture_outcome_digest(
    outcome: &B1CDriveProductionBrokerFixtureOutcome,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = outcome.clone();
    normalized.outcome_sha256 = empty_digest();
    domain_digest(FIXTURE_OUTCOME_DOMAIN, &normalized)
}

pub fn validate_b1_cdrive_production_broker_live_authority_join(
    join: &B1CDriveProductionBrokerFiveAuthorityJoin,
) -> Result<(), B1CDriveProductionBrokerFault> {
    validate_authority_join(join, AuthorityMode::Live)
}

pub fn validate_b1_cdrive_production_broker_fixture_authority_join(
    join: &B1CDriveProductionBrokerFiveAuthorityJoin,
) -> Result<(), B1CDriveProductionBrokerFault> {
    validate_authority_join(join, AuthorityMode::Fixture)
}

#[derive(Clone, Copy)]
enum AuthorityMode {
    Live,
    Fixture,
}

fn validate_authority_join(
    join: &B1CDriveProductionBrokerFiveAuthorityJoin,
    mode: AuthorityMode,
) -> Result<(), B1CDriveProductionBrokerFault> {
    let required = required_b1_cdrive_production_broker_authority_classes();
    if join.records.len() != required.len() {
        return Err(authority_fault("five-authority join count differs"));
    }
    for (record, expected) in join.records.iter().zip(required) {
        if record.class != expected
            || record.artifact_profile.is_empty()
            || record.artifact_profile.len() > 256
            || !valid_digest(&record.artifact_sha256)
            || record.record_sha256 != b1_cdrive_production_broker_authority_record_digest(record)?
        {
            return Err(authority_fault(
                "authority record identity or digest differs",
            ));
        }
        match mode {
            AuthorityMode::Live if record.fixture_only || !record.externally_authenticated => {
                return Err(authority_fault(
                    "fixture or unauthenticated authority cannot satisfy live join",
                ));
            }
            AuthorityMode::Fixture if !record.fixture_only || record.externally_authenticated => {
                return Err(authority_fault(
                    "fixture join attempts to launder live authority",
                ));
            }
            _ => {}
        }
    }
    if join.join_sha256 != b1_cdrive_production_broker_authority_join_digest(join)? {
        return Err(authority_fault("five-authority join digest differs"));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_commission_pair(
    commission: &B1CDriveProductionCommission,
    authorization: &B1CDriveProductionOperatorAuthorization,
    plan_sha256: &ContentDigest,
    fixture_only: bool,
) -> Result<(), B1CDriveProductionBrokerFault> {
    let exact_party = r"THEBRAIN\enjer";
    let exact_subject = "cantor_b1_cdrive_production_broker_p0";
    if commission.profile != B1_CDRIVE_PRODUCTION_COMMISSION_PROFILE
        || authorization.profile != B1_CDRIVE_PRODUCTION_OPERATOR_AUTHORIZATION_PROFILE
        || commission.issuer != exact_party
        || commission.recovery_owner != exact_party
        || authorization.issuer != exact_party
        || commission.subject != exact_subject
        || authorization.subject != exact_subject
        || authorization.role != "operator_authorizer"
        || commission.attempt_uuid != authorization.attempt_uuid
        || commission.conversation_uuid != authorization.conversation_uuid
        || commission.purpose != authorization.purpose
        || commission.plan_sha256 != *plan_sha256
        || authorization.plan_sha256 != *plan_sha256
        || commission.operator_authorization_sha256 != authorization.authorization_sha256
        || commission.maximum_attempts != 1
        || commission.retry_count != 0
        || commission.broker_authored
        || authorization.broker_authored
        || commission.issued_at_unix_millis >= commission.expires_at_unix_millis
        || authorization.issued_at_unix_millis >= authorization.expires_at_unix_millis
        || commission.attempt_uuid.is_empty()
        || commission.purpose.is_empty()
    {
        return Err(commission_fault(
            "commission or authorization binding differs",
        ));
    }
    if commission.fixture_only != fixture_only || authorization.fixture_only != fixture_only {
        return Err(commission_fault(
            "commission fixture/live authority differs",
        ));
    }
    if authorization.authorization_sha256
        != b1_cdrive_production_operator_authorization_digest(authorization)?
        || commission.commission_sha256 != b1_cdrive_production_commission_digest(commission)?
    {
        return Err(commission_fault(
            "commission or authorization self-digest differs",
        ));
    }
    if commission.commission_sha256 == authorization.authorization_sha256 {
        return Err(commission_fault(
            "commission and authorization are not distinct",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_prepared_receipt(
    receipt: &B1CDriveProductionBrokerPreparedReceipt,
    plan_sha256: &ContentDigest,
    phase3a_sha256: &ContentDigest,
    fixture_only: bool,
) -> Result<(), B1CDriveProductionBrokerFault> {
    if receipt.profile != B1_CDRIVE_PRODUCTION_PREPARED_RECEIPT_PROFILE
        || receipt.plan_sha256 != *plan_sha256
        || receipt.phase3a_sha256 != *phase3a_sha256
        || receipt.fixed_ledger_bytes == 0
        || receipt.fixed_ledger_bytes as usize > B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES
        || !receipt.lease_preexisting_regular_nonlink
        || !receipt.ledger_preexisting_regular_nonlink
        || !receipt.evidence_preexisting_directory_nonlink
        || receipt.fixture_only != fixture_only
        || !valid_digest(&receipt.unclaimed_ledger_sha256)
    {
        return Err(authority_fault(
            "prepared receipt authority or bound differs",
        ));
    }
    validate_cdrive_role_path("scratch root", &receipt.scratch_root)?;
    for (label, path) in [
        ("candidate root", &receipt.candidate_root),
        ("evidence root", &receipt.evidence_root),
        ("lease path", &receipt.lease_path),
        ("ledger path", &receipt.ledger_path),
    ] {
        validate_cdrive_role_path(label, path)?;
        if !strict_windows_descendant(path, &receipt.scratch_root) {
            return Err(authority_fault(format!(
                "{label} is not a strict scratch descendant"
            )));
        }
    }
    let roles = [
        &receipt.candidate_root,
        &receipt.evidence_root,
        &receipt.lease_path,
        &receipt.ledger_path,
    ];
    for (index, left) in roles.iter().enumerate() {
        for right in roles.iter().skip(index + 1) {
            if left.eq_ignore_ascii_case(right)
                || strict_windows_descendant(left, right)
                || strict_windows_descendant(right, left)
            {
                return Err(authority_fault("prepared receipt roles overlap"));
            }
        }
    }
    if receipt.prepared_receipt_sha256 != b1_cdrive_production_prepared_receipt_digest(receipt)? {
        return Err(authority_fault("prepared receipt self-digest differs"));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_observation_pair(
    first: &B1CDriveProductionBrokerMutableObservation,
    second: &B1CDriveProductionBrokerMutableObservation,
    plan_sha256: &ContentDigest,
    prepared_receipt_sha256: &ContentDigest,
    phase3a_sha256: &ContentDigest,
) -> Result<(), B1CDriveProductionBrokerFault> {
    for (observation, sequence) in [(first, 1_u8), (second, 2_u8)] {
        if observation.sequence != sequence
            || observation.free_bytes < observation.minimum_free_bytes
            || !observation.reserved_root_present
            || !observation.reserved_ref_present
            || !observation.candidate_clean
            || !observation.sentinels_exact
            || !observation.write_canary_absent
            || !observation.executable_exact
            || observation.broker_process_count != 0
            || observation.plan_sha256 != *plan_sha256
            || observation.prepared_receipt_sha256 != *prepared_receipt_sha256
            || observation.phase3a_sha256 != *phase3a_sha256
            || observation.observed_state_sha256
                != b1_cdrive_production_observed_state_digest(observation)?
            || observation.observation_sha256
                != b1_cdrive_production_observation_digest(observation)?
        {
            return Err(observation_fault(
                "mutable observation truth or digest differs",
            ));
        }
    }
    if first.observed_state_sha256 != second.observed_state_sha256 {
        return Err(observation_fault(
            "mutable state drifted after lease acquisition",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_ledger_fixture(
    ledger: &B1CDriveProductionBrokerLedgerFixture,
    prepared: &B1CDriveProductionBrokerPreparedReceipt,
) -> Result<(), B1CDriveProductionBrokerFault> {
    if ledger.prior_state != B1CDriveProductionBrokerLedgerState::Unclaimed
        || ledger.fixed_ledger_bytes != prepared.fixed_ledger_bytes
        || ledger.prior_bytes_sha256 != prepared.unclaimed_ledger_sha256
        || !valid_digest(&ledger.claimed_bytes_sha256)
        || ledger.prior_bytes_sha256 == ledger.claimed_bytes_sha256
        || !ledger.flush_succeeded
        || !ledger.close_reopen_succeeded
        || !ledger.byte_verification_succeeded
        || !ledger.fixture_only
        || ledger.ledger_sha256 != b1_cdrive_production_ledger_fixture_digest(ledger)?
    {
        return Err(ledger_fault("fixed one-use ledger fixture differs"));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_child_accounts(
    accounts: &[B1CDriveProductionBrokerChildAccount],
) -> Result<(), B1CDriveProductionBrokerFault> {
    use B1CDrivePreflightProducerChildKind as Kind;
    let expected = [
        Kind::Version,
        Kind::StandardSchema,
        Kind::ExperimentalSchema,
        Kind::AppServer,
    ];
    if accounts.len() != expected.len() {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Containment,
            "direct child account count differs",
        ));
    }
    let mut aggregate_total = 0_u32;
    for (index, (account, kind)) in accounts.iter().zip(expected).enumerate() {
        let (maximum_active, maximum_total) = if kind == Kind::AppServer {
            (2, 4)
        } else {
            (1, 1)
        };
        aggregate_total = aggregate_total
            .checked_add(account.total_processes)
            .ok_or_else(|| {
                fault(
                    B1CDriveProductionBrokerFaultCode::Bound,
                    "aggregate job process count overflowed",
                )
            })?;
        if account.sequence != (index + 1) as u8
            || account.kind != kind
            || !account.job_created_before_process
            || !account.kill_on_close
            || account.breakaway_enabled
            || account.inherited_handle_count != 3
            || !account.process_created_suspended
            || !account.assigned_before_resume
            || account.resume_previous_count != 1
            || account.maximum_active_processes != maximum_active
            || account.total_processes == 0
            || account.total_processes > maximum_total
            || account.active_processes_at_terminal != 0
            || account.late_output
            || account.stdout_over_bound
            || account.stderr_over_bound
            || account.timed_out
            || account.forced_termination
            || account.exit_code != 0
        {
            return Err(fault(
                B1CDriveProductionBrokerFaultCode::Containment,
                "child containment or accounting truth differs",
            ));
        }
    }
    if aggregate_total > u32::from(EXPECTED_AGGREGATE_JOB_PROCESS_MAXIMUM) {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Containment,
            "aggregate job process count exceeds seven",
        ));
    }
    Ok(())
}

pub fn validate_b1_cdrive_production_transcript_account(
    plan: &B1CDrivePreflightProducerPlan,
    account: &B1CDriveProductionBrokerTranscriptAccount,
) -> Result<(), B1CDriveProductionBrokerFault> {
    if account.frames.len() != EXPECTED_TOTAL_FRAME_COUNT as usize
        || plan.outbound_frames.len() != EXPECTED_OUTBOUND_FRAME_COUNT as usize
    {
        return Err(evidence_fault("transcript frame count differs"));
    }
    let mut aggregate_bytes = 0_usize;
    for (index, frame) in account.frames.iter().enumerate() {
        let bytes = serde_json::to_vec(frame).map_err(machine_fault)?;
        if bytes.len() > B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES {
            return Err(evidence_fault("transcript frame exceeds JSONL bound"));
        }
        aggregate_bytes = aggregate_bytes.checked_add(bytes.len()).ok_or_else(|| {
            fault(
                B1CDriveProductionBrokerFaultCode::Bound,
                "transcript aggregate byte count overflowed",
            )
        })?;
        if index % 2 == 0 {
            if frame != &plan.outbound_frames[index / 2] {
                return Err(evidence_fault(
                    "outbound transcript frame order or bytes differ",
                ));
            }
            continue;
        }
        let object = frame
            .as_object()
            .ok_or_else(|| evidence_fault("incoming transcript frame is not an object"))?;
        if index == 3 {
            if object.len() != 2
                || object.get("method").and_then(Value::as_str)
                    != Some("remoteControl/status/changed")
                || !object.contains_key("params")
            {
                return Err(evidence_fault("status notification shape differs"));
            }
            continue;
        }
        let expected_id = match index {
            1 => 0,
            5 => 1,
            7 => 2,
            9 => 3,
            11 => 4,
            _ => return Err(evidence_fault("incoming transcript position differs")),
        };
        let id = object
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| evidence_fault("incoming response id is absent"))?;
        if object.len() != 2
            || (object.contains_key("result") == object.contains_key("error"))
            || id != expected_id
        {
            return Err(evidence_fault("incoming response shape differs"));
        }
    }
    if aggregate_bytes > 64 * 1024 * 1024 {
        return Err(evidence_fault(
            "transcript method closure position or aggregate differs",
        ));
    }
    if account.allowed_read_exit_code != 0
        || account.allowed_read_stdout != "SWA05_B1_ALLOWED_READ_SENTINEL\n"
        || !account.allowed_read_stderr.is_empty()
        || account.denied_read_exit_code == 0
        || !account.denied_read_stdout.is_empty()
        || account.denied_read_stderr != "Access is denied.\r\n"
        || account.denied_write_exit_code == 0
        || !account.denied_write_stdout.is_empty()
        || account.denied_write_stderr != "Access is denied.\r\n"
        || account.denied_sentinel_disclosed
        || account.write_sentinel_disclosed
        || account.write_canary_present
    {
        return Err(evidence_fault(
            "permission-profile transcript consequences differ",
        ));
    }
    Ok(())
}

pub fn run_b1_cdrive_production_broker_fixture(
    input: &B1CDriveProductionBrokerFixtureInput,
) -> Result<B1CDriveProductionBrokerFixtureOutcome, B1CDriveProductionBrokerFault> {
    let request = validate_fixture_input(input)?;
    let plan = validate_request(&request)?;
    let mut execution = FixtureExecution::new();
    execution.call("validate_inputs")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::BeforeLease) {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::InputsValidated);
    }

    execution.transition(B1CDriveProductionBrokerState::LeaseHeld, false, false)?;
    execution.lease_guard = Some(B1CDriveFixtureLeaseGuard::acquire());
    execution.call("acquire_exclusive_lease")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::AfterLease) {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::LeaseHeld);
    }

    execution.transition(B1CDriveProductionBrokerState::StateReobserved, false, false)?;
    execution.require_lease()?;
    execution.call("reobserve_mutable_state")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::AfterReobserve) {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::StateReobserved);
    }

    execution.transition(
        B1CDriveProductionBrokerState::ConsumptionClaimed,
        true,
        false,
    )?;
    execution.claimed_ledger_guard = Some(B1CDriveFixtureClaimedLedgerGuard::claim(
        &input.ledger,
        execution.require_lease()?,
    )?);
    execution.call("claim_flush_reopen_verify_ledger")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::AfterClaim) {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::ConsumptionClaimed);
    }

    let capability = execution.issue_fake_capability(input)?;
    execution.transition(B1CDriveProductionBrokerState::PermitIssued, true, true)?;
    execution.call("issue_fake_execution_capability")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::AfterTestCapability) {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::PermitIssued);
    }

    execution.transition(B1CDriveProductionBrokerState::ChildrenRunning, true, true)?;
    execution.call("begin_fake_child_sequence")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::DuringChildren) {
        execution.call("execute_fake_child:version")?;
        return execution.finish_failure(input, B1CDriveProductionBrokerState::ChildrenRunning);
    }
    consume_fake_execution_capability(capability, &plan, &mut execution)?;

    execution.transition(B1CDriveProductionBrokerState::EvidenceRetained, true, false)?;
    execution.evidence_retained = true;
    execution.call("retain_append_only_evidence")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::AfterEvidenceRetention)
    {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::EvidenceRetained);
    }

    execution.transition(
        B1CDriveProductionBrokerState::CommissionConsumed,
        true,
        false,
    )?;
    execution.commission_consumed = true;
    execution.call("mark_commission_consumed")?;
    if input.fault_point
        == Some(B1CDriveProductionBrokerFixtureFaultPoint::AfterCommissionConsumption)
    {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::CommissionConsumed);
    }

    execution.transition(B1CDriveProductionBrokerState::LeaseReleased, true, false)?;
    execution.release_lease()?;
    execution.call("release_exclusive_lease")?;
    if input.fault_point == Some(B1CDriveProductionBrokerFixtureFaultPoint::AfterLeaseRelease) {
        return execution.finish_failure(input, B1CDriveProductionBrokerState::LeaseReleased);
    }

    execution.transition(B1CDriveProductionBrokerState::Complete, true, false)?;
    execution.call("complete")?;
    execution.finish(input, B1CDriveProductionBrokerState::Complete)
}

pub fn validate_b1_cdrive_production_broker_fixture_outcome(
    input: &B1CDriveProductionBrokerFixtureInput,
    outcome: &B1CDriveProductionBrokerFixtureOutcome,
) -> Result<(), B1CDriveProductionBrokerFault> {
    let expected = run_b1_cdrive_production_broker_fixture(input)?;
    if &expected != outcome {
        return Err(evidence_fault(
            "fixture outcome differs from deterministic replay",
        ));
    }
    Ok(())
}

fn validate_fixture_input(
    input: &B1CDriveProductionBrokerFixtureInput,
) -> Result<B1CDriveProductionBrokerImplementationRequest, B1CDriveProductionBrokerFault> {
    if input.profile != B1_CDRIVE_PRODUCTION_BROKER_FIXTURE_INPUT_PROFILE
        || input.input_sha256 != b1_cdrive_production_broker_fixture_input_digest(input)?
    {
        return Err(evidence_fault(
            "fixture input profile or self-digest differs",
        ));
    }
    let request = from_b1_cdrive_production_broker_implementation_request_machine_form(
        &input.implementation_request_machine_form,
    )?;
    let plan = validate_request(&request)?;
    validate_b1_cdrive_production_broker_fixture_authority_join(&input.authorities)?;
    validate_b1_cdrive_production_commission_pair(
        &input.commission,
        &input.operator_authorization,
        &plan.plan_sha256,
        true,
    )?;
    if input.commission.implementation_commit != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT
        || input.commission.implementation_bookend != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND
    {
        return Err(commission_fault(
            "fixture commission implementation lineage differs",
        ));
    }
    validate_b1_cdrive_production_prepared_receipt(
        &input.prepared_receipt,
        &plan.plan_sha256,
        &input.commission.phase3a_sha256,
        true,
    )?;
    if input.commission.prepared_receipt_sha256 != input.prepared_receipt.prepared_receipt_sha256
        || input.prepared_receipt.phase3a_sha256 != input.commission.phase3a_sha256
    {
        return Err(authority_fault(
            "commission and prepared receipt join differs",
        ));
    }
    validate_b1_cdrive_production_observation_pair(
        &input.first_observation,
        &input.second_observation,
        &plan.plan_sha256,
        &input.prepared_receipt.prepared_receipt_sha256,
        &input.commission.phase3a_sha256,
    )?;
    if input.first_observation.expected_current_commit != input.commission.expected_current_commit
        || input.second_observation.expected_current_commit
            != input.commission.expected_current_commit
    {
        return Err(observation_fault(
            "expected-current observation binding differs",
        ));
    }
    validate_b1_cdrive_production_ledger_fixture(&input.ledger, &input.prepared_receipt)?;
    Ok(request)
}

struct B1CDriveFakeExecutionCapability {
    attempt_sha256: ContentDigest,
    second_observation_sha256: ContentDigest,
    claimed_ledger_sha256: ContentDigest,
}

fn consume_fake_execution_capability(
    capability: B1CDriveFakeExecutionCapability,
    plan: &B1CDrivePreflightProducerPlan,
    execution: &mut FixtureExecution,
) -> Result<(), B1CDriveProductionBrokerFault> {
    if !valid_digest(&capability.attempt_sha256)
        || !valid_digest(&capability.second_observation_sha256)
        || !valid_digest(&capability.claimed_ledger_sha256)
        || plan.children.len() != 4
    {
        return Err(state_fault(
            "fake execution capability or child plan differs",
        ));
    }
    for child in &plan.children {
        let kind = match child.kind {
            B1CDrivePreflightProducerChildKind::Version => "version",
            B1CDrivePreflightProducerChildKind::StandardSchema => "standard_schema",
            B1CDrivePreflightProducerChildKind::ExperimentalSchema => "experimental_schema",
            B1CDrivePreflightProducerChildKind::AppServer => "app_server",
        };
        execution.call(&format!("execute_fake_child:{kind}"))?;
    }
    execution.fake_execution_capability_consumed = true;
    Ok(())
}

struct B1CDriveFixtureLeaseGuard {
    held: bool,
}

impl B1CDriveFixtureLeaseGuard {
    fn acquire() -> Self {
        Self { held: true }
    }

    fn release(mut self) {
        self.held = false;
    }
}

struct B1CDriveFixtureClaimedLedgerGuard {
    claimed_bytes_sha256: ContentDigest,
}

impl B1CDriveFixtureClaimedLedgerGuard {
    fn claim(
        ledger: &B1CDriveProductionBrokerLedgerFixture,
        lease: &B1CDriveFixtureLeaseGuard,
    ) -> Result<Self, B1CDriveProductionBrokerFault> {
        if !lease.held
            || ledger.prior_state != B1CDriveProductionBrokerLedgerState::Unclaimed
            || !ledger.flush_succeeded
            || !ledger.close_reopen_succeeded
            || !ledger.byte_verification_succeeded
        {
            return Err(ledger_fault(
                "ledger claim lacks a continuous lease or durable verification",
            ));
        }
        Ok(Self {
            claimed_bytes_sha256: ledger.claimed_bytes_sha256.clone(),
        })
    }
}

struct FixtureExecution {
    state: B1CDriveProductionBrokerState,
    transitions: Vec<B1CDriveProductionBrokerTransition>,
    call_ledger: Vec<String>,
    lease_guard: Option<B1CDriveFixtureLeaseGuard>,
    claimed_ledger_guard: Option<B1CDriveFixtureClaimedLedgerGuard>,
    evidence_retained: bool,
    commission_consumed: bool,
    fake_execution_capability_consumed: bool,
}

impl FixtureExecution {
    fn new() -> Self {
        Self {
            state: B1CDriveProductionBrokerState::InputsValidated,
            transitions: Vec::new(),
            call_ledger: Vec::new(),
            lease_guard: None,
            claimed_ledger_guard: None,
            evidence_retained: false,
            commission_consumed: false,
            fake_execution_capability_consumed: false,
        }
    }

    fn call(&mut self, value: &str) -> Result<(), B1CDriveProductionBrokerFault> {
        if self.call_ledger.len() >= 128 || value.len() > 128 {
            return Err(state_fault("fake backend call ledger exceeds bound"));
        }
        self.call_ledger.push(value.to_owned());
        Ok(())
    }

    fn require_lease(&self) -> Result<&B1CDriveFixtureLeaseGuard, B1CDriveProductionBrokerFault> {
        self.lease_guard
            .as_ref()
            .filter(|guard| guard.held)
            .ok_or_else(|| {
                fault(
                    B1CDriveProductionBrokerFaultCode::Lease,
                    "lease guard is absent",
                )
            })
    }

    fn issue_fake_capability(
        &self,
        input: &B1CDriveProductionBrokerFixtureInput,
    ) -> Result<B1CDriveFakeExecutionCapability, B1CDriveProductionBrokerFault> {
        self.require_lease()?;
        let ledger = self
            .claimed_ledger_guard
            .as_ref()
            .ok_or_else(|| ledger_fault("claimed ledger guard is absent"))?;
        Ok(B1CDriveFakeExecutionCapability {
            attempt_sha256: input.commission.commission_sha256.clone(),
            second_observation_sha256: input.second_observation.observation_sha256.clone(),
            claimed_ledger_sha256: ledger.claimed_bytes_sha256.clone(),
        })
    }

    fn release_lease(&mut self) -> Result<(), B1CDriveProductionBrokerFault> {
        let guard = self.lease_guard.take().ok_or_else(|| {
            fault(
                B1CDriveProductionBrokerFaultCode::Lease,
                "lease released early",
            )
        })?;
        guard.release();
        Ok(())
    }

    fn transition(
        &mut self,
        to: B1CDriveProductionBrokerState,
        claimed: bool,
        process_allowed: bool,
    ) -> Result<(), B1CDriveProductionBrokerFault> {
        let sequence = u8::try_from(self.transitions.len() + 1)
            .map_err(|_| state_fault("transition count exceeds bound"))?;
        self.transitions.push(B1CDriveProductionBrokerTransition {
            sequence,
            from: self.state,
            to,
            consumption_claimed_after: claimed,
            process_creation_allowed_after: process_allowed,
        });
        self.state = to;
        Ok(())
    }

    fn finish_failure(
        mut self,
        input: &B1CDriveProductionBrokerFixtureInput,
        state: B1CDriveProductionBrokerState,
    ) -> Result<B1CDriveProductionBrokerFixtureOutcome, B1CDriveProductionBrokerFault> {
        let terminal = b1_cdrive_production_broker_failure_terminal(state);
        self.transition(terminal, self.claimed_ledger_guard.is_some(), false)?;
        self.call(match terminal {
            B1CDriveProductionBrokerState::NotRun => "retain_not_run_truth",
            _ => "retain_quarantined_truth",
        })?;
        self.finish(input, terminal)
    }

    fn finish(
        self,
        input: &B1CDriveProductionBrokerFixtureInput,
        terminal: B1CDriveProductionBrokerState,
    ) -> Result<B1CDriveProductionBrokerFixtureOutcome, B1CDriveProductionBrokerFault> {
        validate_b1_cdrive_production_broker_transition_trace(&self.transitions)?;
        let mut outcome = B1CDriveProductionBrokerFixtureOutcome {
            profile: B1_CDRIVE_PRODUCTION_BROKER_FIXTURE_OUTCOME_PROFILE.to_owned(),
            terminal_state: terminal,
            transitions: self.transitions,
            call_ledger: self.call_ledger,
            lease_held_at_terminal: self.lease_guard.is_some(),
            ledger_claimed: self.claimed_ledger_guard.is_some(),
            evidence_retained: self.evidence_retained,
            commission_consumed: self.commission_consumed,
            may_have_mutated: terminal == B1CDriveProductionBrokerState::Quarantined,
            private_execution_permit_constructed: false,
            fake_execution_capability_consumed: self.fake_execution_capability_consumed,
            windows_backend_invoked: false,
            retry_count: input.commission.retry_count,
            cleanup_count: 0,
            effect_account: zero_effect_account(),
            outcome_sha256: empty_digest(),
        };
        outcome.outcome_sha256 = b1_cdrive_production_broker_fixture_outcome_digest(&outcome)?;
        Ok(outcome)
    }
}

fn zero_effect_account() -> B1CDriveProductionBrokerEffectAccount {
    B1CDriveProductionBrokerEffectAccount {
        physical_contact: false,
        process_creation_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        network_contact_count: 0,
        writer_run_count: 0,
        git_mutation_count: 0,
        publication_count: 0,
        persistence_count: 0,
        activation_count: 0,
        d_drive_contact_count: 0,
        remote_contact_count: 0,
        fpga_contact_count: 0,
        minecraft_contact_count: 0,
        wsl_compile_count: 0,
        cleanup_count: 0,
        foreign_effect_count: 0,
    }
}

pub fn verify_b1_cdrive_production_broker_activation_lock()
-> Result<(), B1CDriveProductionBrokerFault> {
    match PHYSICAL_ACTIVATION_DIGEST {
        None => Err(fault(
            B1CDriveProductionBrokerFaultCode::Activation,
            "physical activation digest is not configured",
        )),
        Some(_) => Err(fault(
            B1CDriveProductionBrokerFaultCode::Activation,
            "physical activation requires a later implementation revision",
        )),
    }
}

#[cfg(windows)]
pub fn execute_b1_cdrive_windows_contained_child(
    spec: &B1CDriveWindowsContainedChildSpec,
) -> Result<B1CDriveWindowsContainedChildObservation, B1CDriveProductionBrokerFault> {
    let permit = issue_physical_execution_permit(&spec.attempt_sha256)?;
    crate::self_work_update_broker_b1_cdrive_windows_containment::run_contained_child(&permit, spec)
        .map_err(|message| fault(B1CDriveProductionBrokerFaultCode::Containment, message))
}

#[cfg(windows)]
fn issue_physical_execution_permit(
    attempt_sha256: &ContentDigest,
) -> Result<B1CDrivePhysicalExecutionPermit, B1CDriveProductionBrokerFault> {
    verify_b1_cdrive_production_broker_activation_lock()?;
    if attempt_sha256.algorithm != "sha256"
        || attempt_sha256.value.len() != 64
        || !attempt_sha256
            .value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Activation,
            "physical attempt digest differs",
        ));
    }
    Ok(B1CDrivePhysicalExecutionPermit {
        attempt_sha256: attempt_sha256.clone(),
    })
}

pub fn to_b1_cdrive_production_broker_implementation_request_machine_form(
    request: &B1CDriveProductionBrokerImplementationRequest,
) -> Result<String, B1CDriveProductionBrokerFault> {
    validate_request(request)?;
    serialize_bounded(request)
}

pub fn from_b1_cdrive_production_broker_implementation_request_machine_form(
    value: &str,
) -> Result<B1CDriveProductionBrokerImplementationRequest, B1CDriveProductionBrokerFault> {
    let request: B1CDriveProductionBrokerImplementationRequest = parse_strict_bounded(value)?;
    validate_request(&request)?;
    if serialize_bounded(&request)? != value {
        return Err(machine_fault(
            "production-broker implementation request is not canonical compact JSON",
        ));
    }
    Ok(request)
}

pub fn to_b1_cdrive_production_broker_implementation_receipt_machine_form(
    request: &B1CDriveProductionBrokerImplementationRequest,
    receipt: &B1CDriveProductionBrokerImplementationReceipt,
) -> Result<String, B1CDriveProductionBrokerFault> {
    validate_b1_cdrive_production_broker_implementation_receipt(request, receipt)?;
    serialize_bounded(receipt)
}

pub fn from_b1_cdrive_production_broker_implementation_receipt_machine_form(
    request: &B1CDriveProductionBrokerImplementationRequest,
    value: &str,
) -> Result<B1CDriveProductionBrokerImplementationReceipt, B1CDriveProductionBrokerFault> {
    let receipt: B1CDriveProductionBrokerImplementationReceipt = parse_strict_bounded(value)?;
    validate_b1_cdrive_production_broker_implementation_receipt(request, &receipt)?;
    if serialize_bounded(&receipt)? != value {
        return Err(machine_fault(
            "production-broker implementation receipt is not canonical compact JSON",
        ));
    }
    Ok(receipt)
}

pub fn to_b1_cdrive_production_broker_fixture_input_machine_form(
    input: &B1CDriveProductionBrokerFixtureInput,
) -> Result<String, B1CDriveProductionBrokerFault> {
    validate_fixture_input(input)?;
    serialize_bounded(input)
}

pub fn from_b1_cdrive_production_broker_fixture_input_machine_form(
    value: &str,
) -> Result<B1CDriveProductionBrokerFixtureInput, B1CDriveProductionBrokerFault> {
    let input: B1CDriveProductionBrokerFixtureInput = parse_strict_bounded(value)?;
    validate_fixture_input(&input)?;
    if serialize_bounded(&input)? != value {
        return Err(machine_fault(
            "production-broker fixture input is not canonical compact JSON",
        ));
    }
    Ok(input)
}

pub fn to_b1_cdrive_production_broker_fixture_outcome_machine_form(
    input: &B1CDriveProductionBrokerFixtureInput,
    outcome: &B1CDriveProductionBrokerFixtureOutcome,
) -> Result<String, B1CDriveProductionBrokerFault> {
    validate_b1_cdrive_production_broker_fixture_outcome(input, outcome)?;
    serialize_bounded(outcome)
}

pub fn from_b1_cdrive_production_broker_fixture_outcome_machine_form(
    input: &B1CDriveProductionBrokerFixtureInput,
    value: &str,
) -> Result<B1CDriveProductionBrokerFixtureOutcome, B1CDriveProductionBrokerFault> {
    let outcome: B1CDriveProductionBrokerFixtureOutcome = parse_strict_bounded(value)?;
    validate_b1_cdrive_production_broker_fixture_outcome(input, &outcome)?;
    if serialize_bounded(&outcome)? != value {
        return Err(machine_fault(
            "production-broker fixture outcome is not canonical compact JSON",
        ));
    }
    Ok(outcome)
}

pub fn b1_cdrive_production_broker_implementation_request_digest(
    request: &B1CDriveProductionBrokerImplementationRequest,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn b1_cdrive_production_broker_implementation_receipt_digest(
    receipt: &B1CDriveProductionBrokerImplementationReceipt,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty_digest();
    domain_digest(RECEIPT_DOMAIN, &normalized)
}

fn validate_request(
    request: &B1CDriveProductionBrokerImplementationRequest,
) -> Result<B1CDrivePreflightProducerPlan, B1CDriveProductionBrokerFault> {
    if request.profile != B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_REQUEST_PROFILE
        || request.source_snapshot_uuid != B1_CDRIVE_PRODUCTION_BROKER_SOURCE_SNAPSHOT_UUID
        || request.canonical_uuid != B1_CDRIVE_PRODUCTION_BROKER_CANONICAL_UUID
        || request.signature_uuid != B1_CDRIVE_PRODUCTION_BROKER_SIGNATURE_UUID
        || request.formation_commit != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_COMMIT
        || request.formation_bookend != B1_CDRIVE_PRODUCTION_BROKER_FORMATION_BOOKEND
    {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Lineage,
            "production-broker implementation lineage differs",
        ));
    }
    if request.physical_activation_digest.is_some() {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Activation,
            "implementation request attempts to configure physical activation",
        ));
    }
    if request.request_sha256 != b1_cdrive_production_broker_implementation_request_digest(request)?
    {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Digest,
            "production-broker implementation request self-digest differs",
        ));
    }
    let producer_request: B1CDrivePreflightProducerPlanRequest =
        from_b1_cdrive_preflight_producer_plan_request_machine_form(
            &request.producer_plan_request_machine_form,
        )
        .map_err(producer_fault)?;
    let plan = from_b1_cdrive_preflight_producer_plan_machine_form(
        &producer_request,
        &request.producer_plan_machine_form,
    )
    .map_err(producer_fault)?;
    validate_b1_cdrive_preflight_producer_plan(&producer_request, &plan).map_err(producer_fault)?;
    if plan.children.len() != EXPECTED_DIRECT_CHILD_COUNT as usize
        || plan.expected_incoming_frame_count != EXPECTED_INCOMING_FRAME_COUNT
        || plan.expected_total_transcript_frame_count != EXPECTED_TOTAL_FRAME_COUNT
        || plan.environment.len() != EXPECTED_ENVIRONMENT_NAME_COUNT as usize
        || plan.denied_environment.len() != EXPECTED_DENIED_ENVIRONMENT_NAME_COUNT as usize
        || plan.next_required_authorities != REQUIRED_AUTHORITIES.map(str::to_owned)
        || plan.physical_execution_authorized
        || plan.physical_run_count != 0
    {
        return Err(producer_fault("producer plan authority or count differs"));
    }
    Ok(plan)
}

fn domain_digest(
    domain: &str,
    value: &impl Serialize,
) -> Result<ContentDigest, B1CDriveProductionBrokerFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn serialize_bounded(value: &impl Serialize) -> Result<String, B1CDriveProductionBrokerFault> {
    let machine_form = serde_json::to_string(value).map_err(machine_fault)?;
    if machine_form.len() > B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Bound,
            "production-broker machine form exceeds byte bound",
        ));
    }
    Ok(machine_form)
}

fn parse_strict_bounded<T: DeserializeOwned>(
    value: &str,
) -> Result<T, B1CDriveProductionBrokerFault> {
    if value.len() > B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1CDriveProductionBrokerFaultCode::Bound,
            "production-broker machine form exceeds byte bound",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(value);
    StrictSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(machine_fault)?;
    deserializer.end().map_err(machine_fault)?;
    serde_json::from_str(value).map_err(machine_fault)
}

#[derive(Debug)]
struct StrictValue;

struct StrictSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting exceeds bound"));
        }
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

struct StrictVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded duplicate-free JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))
            .map(|_| StrictValue)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }
    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(StrictSeed {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(StrictValue)
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            if keys.len() > MAX_JSON_FIELDS {
                return Err(de::Error::custom("JSON object field count exceeds bound"));
            }
            map.next_value_seed(StrictSeed {
                depth: self.depth + 1,
            })?;
        }
        Ok(StrictValue)
    }
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn fault(
    code: B1CDriveProductionBrokerFaultCode,
    message: impl Into<String>,
) -> B1CDriveProductionBrokerFault {
    B1CDriveProductionBrokerFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1CDriveProductionBrokerFault {
    fault(
        B1CDriveProductionBrokerFaultCode::MachineForm,
        error.to_string(),
    )
}

fn producer_fault(error: impl fmt::Display) -> B1CDriveProductionBrokerFault {
    fault(
        B1CDriveProductionBrokerFaultCode::ProducerPlan,
        error.to_string(),
    )
}

fn state_fault(message: impl Into<String>) -> B1CDriveProductionBrokerFault {
    fault(B1CDriveProductionBrokerFaultCode::State, message)
}

fn authority_fault(message: impl Into<String>) -> B1CDriveProductionBrokerFault {
    fault(B1CDriveProductionBrokerFaultCode::Authority, message)
}

fn commission_fault(message: impl Into<String>) -> B1CDriveProductionBrokerFault {
    fault(B1CDriveProductionBrokerFaultCode::Commission, message)
}

fn ledger_fault(message: impl Into<String>) -> B1CDriveProductionBrokerFault {
    fault(B1CDriveProductionBrokerFaultCode::Ledger, message)
}

fn observation_fault(message: impl Into<String>) -> B1CDriveProductionBrokerFault {
    fault(B1CDriveProductionBrokerFaultCode::Observation, message)
}

fn evidence_fault(message: impl Into<String>) -> B1CDriveProductionBrokerFault {
    fault(B1CDriveProductionBrokerFaultCode::Evidence, message)
}

fn valid_digest(digest: &ContentDigest) -> bool {
    digest.algorithm == "sha256"
        && digest.value.len() == 64
        && digest.value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_cdrive_role_path(
    label: &str,
    value: &str,
) -> Result<(), B1CDriveProductionBrokerFault> {
    if value.len() > 1024
        || value.contains(['\0', '\r', '\n'])
        || value.len() < 3
        || !value.as_bytes()[0].eq_ignore_ascii_case(&b'C')
        || value.as_bytes()[1] != b':'
        || !matches!(value.as_bytes()[2], b'\\' | b'/')
        || value.split(['\\', '/']).any(|part| part == "..")
    {
        return Err(authority_fault(format!(
            "{label} is not a bounded absolute C-drive path"
        )));
    }
    Ok(())
}

fn strict_windows_descendant(candidate: &str, parent: &str) -> bool {
    let candidate = candidate.replace('/', "\\");
    let mut parent = parent.replace('/', "\\");
    while parent.ends_with('\\') {
        parent.pop();
    }
    candidate.len() > parent.len()
        && candidate[..parent.len()].eq_ignore_ascii_case(&parent)
        && candidate.as_bytes().get(parent.len()) == Some(&b'\\')
}
