//! Closed producer plan for the signed C-drive B1 permission-profile preflight.
//!
//! This module closes the exact executable, environment, schema-generation,
//! App Server, and transcript request plan. It deliberately has no process or
//! filesystem-write surface. A later production broker may execute the plan
//! only after authentic commission, continuous lease, durable consumption,
//! retained preparation, and fresh Phase3A authority exist.

use std::fmt;

use cantor_core::{ContentDigest, sha256_bytes};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Number, Value, json};

use crate::{
    CDriveWorktreePreparationRequest, PreparationCommissionAdmissionAuthority,
    PreparationCommissionAdmissionReceipt, PreparationCommissionAdmissionStatus,
    PreparationFilesystemObservation, PreparationGitObservation, PreparationOutcomeAccount,
    PreparationOutcomeDisposition, from_cdrive_worktree_preparation_filesystem_machine_form,
    from_cdrive_worktree_preparation_git_observation_machine_form,
    from_cdrive_worktree_preparation_outcome_machine_form,
    from_cdrive_worktree_preparation_request_machine_form,
    from_preparation_commission_admission_receipt_machine_form,
    to_preparation_commission_admission_receipt_machine_form,
    validate_cdrive_worktree_prepared_observations,
};

pub const B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_REQUEST_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preflight-producer-plan-request/0.2";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_PROFILE: &str =
    "cantor-self-work-update-broker-b1-cdrive-preflight-producer-plan/0.2";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_STATUS: &str =
    "bounded_producer_plan_verified_physical_run_gated";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_AUTHORITY: &str = "provider_free_plan_only";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_SIGNATURE_UUID: &str =
    "fb179473-303c-47a7-981d-25479019c1e0";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_SOURCE_SNAPSHOT_UUID: &str =
    "661679ac-325d-4dc2-808d-232d732027b5";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE: &str = "C:\\Users\\enjer\\AppData\\Roaming\\npm\\node_modules\\@openai\\codex\\node_modules\\@openai\\codex-win32-x64\\vendor\\x86_64-pc-windows-msvc\\bin\\codex.exe";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE_BYTES: u64 = 242_541_872;
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE_SHA256: &str =
    "FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_STANDARD_SCHEMA_SHA256: &str =
    "99B3E93A3E5C96554E23A0B9EFB9FA4BDD1B05699CCB72B86A4F6A5CD69350E8";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_EXPERIMENTAL_SCHEMA_SHA256: &str =
    "3846D4F0D17D301277E9809AE6F69C9E552CEAD5385476E3B9B4F83211DF9AD2";
pub const B1_CDRIVE_PREFLIGHT_PRODUCER_MAX_MACHINE_FORM_BYTES: usize = 2 * 1024 * 1024;

const REQUEST_DOMAIN: &str =
    "cantor.self-work-update-broker.b1.cdrive-preflight-producer-plan-request.v2";
const PLAN_DOMAIN: &str = "cantor.self-work-update-broker.b1.cdrive-preflight-producer-plan.v2";
const PROFILE_ID: &str = "swa05_b1_preflight";
const COMMAND_EXECUTABLE: &str = "C:\\Windows\\System32\\cmd.exe";
const WRITE_SENTINEL: &str = "SWA05_B1_DENIED_WRITE_SENTINEL";
const SENTINEL_ROOT: &str = "fixtures\\swa05_b1_cdrive_preflight";
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_FIELDS: usize = 256;

const ENVIRONMENT_NAMES: [&str; 7] = [
    "CODEX_HOME",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "WINDIR",
];

const DENIED_ENVIRONMENT_NAMES: [&str; 16] = [
    "ALL_PROXY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_OPENAI_API_KEY",
    "CODEX_API_KEY",
    "EDITOR",
    "GH_TOKEN",
    "GIT_ASKPASS",
    "GIT_CONFIG_GLOBAL",
    "GIT_SSH_COMMAND",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "OPENAI_API_KEY",
    "PAGER",
    "VISUAL",
];

const EVIDENCE_ARTIFACT_NAMES: [&str; 9] = [
    "current_admission.json",
    "experimental_schema.json",
    "handoff_proposal.json",
    "handoff_request.json",
    "observation.json",
    "prior_admission.json",
    "protocol_request.json",
    "protocol_result.json",
    "standard_schema.json",
];

const NEXT_REQUIRED_AUTHORITIES: [&str; 5] = [
    "authenticated_external_commission",
    "continuous_exclusive_lease",
    "durable_consumption_claim",
    "production_broker_prepared_receipt",
    "fresh_phase3a_replay",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightProducerEnvironmentValue {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightProducerPlanRequest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub signature_uuid: String,
    pub commission_admission_receipt_machine_form: String,
    pub preparation_request_machine_form: String,
    pub preparation_filesystem_machine_form: String,
    pub preparation_git_machine_form: String,
    pub preparation_outcome_machine_form: String,
    pub environment: Vec<B1CDrivePreflightProducerEnvironmentValue>,
    pub request_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B1CDrivePreflightProducerChildKind {
    Version,
    StandardSchema,
    ExperimentalSchema,
    AppServer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightProducerChildSpec {
    pub sequence: u8,
    pub kind: B1CDrivePreflightProducerChildKind,
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub environment_clear_first: bool,
    pub stdin_jsonl: bool,
    pub maximum_stdout_bytes: u64,
    pub maximum_stderr_bytes: u64,
    pub timeout_millis: u64,
    pub terminate_on_timeout: bool,
    pub wait_after_terminate: bool,
    pub require_descendant_free: bool,
    pub require_late_output_free: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct B1CDrivePreflightProducerPlan {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub signature_uuid: String,
    pub request_sha256: ContentDigest,
    pub commission_admission_receipt_sha256: ContentDigest,
    pub preparation_request_sha256: ContentDigest,
    pub preparation_filesystem_sha256: ContentDigest,
    pub preparation_git_sha256: ContentDigest,
    pub preparation_outcome_sha256: ContentDigest,
    pub selected_executable: String,
    pub selected_executable_bytes: u64,
    pub selected_executable_sha256: String,
    pub selected_executable_version: String,
    pub standard_schema_sha256: String,
    pub experimental_schema_sha256: String,
    pub permission_profile_id: String,
    pub filesystem_override: String,
    pub network_enabled: bool,
    pub environment: Vec<B1CDrivePreflightProducerEnvironmentValue>,
    pub denied_environment: Vec<String>,
    pub children: Vec<B1CDrivePreflightProducerChildSpec>,
    pub outbound_frames: Vec<Value>,
    pub expected_incoming_frame_count: u8,
    pub expected_total_transcript_frame_count: u8,
    pub evidence_artifact_names: Vec<String>,
    pub maximum_inventory_entries: u16,
    pub maximum_process_count: u8,
    pub physical_execution_authorized: bool,
    pub physical_run_count: u8,
    pub provider_trial_count: u8,
    pub model_turn_count: u8,
    pub mcp_call_count: u8,
    pub network_contact_count: u8,
    pub d_drive_contact_count: u8,
    pub cleanup_count: u8,
    pub next_required_authorities: Vec<String>,
    pub plan_sha256: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B1CDrivePreflightProducerPlanFaultCode {
    MachineForm,
    Lineage,
    Commission,
    Preparation,
    Environment,
    Bound,
    Plan,
    Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B1CDrivePreflightProducerPlanFault {
    pub code: B1CDrivePreflightProducerPlanFaultCode,
    pub message: String,
}

impl fmt::Display for B1CDrivePreflightProducerPlanFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for B1CDrivePreflightProducerPlanFault {}

pub fn compile_b1_cdrive_preflight_producer_plan(
    request: &B1CDrivePreflightProducerPlanRequest,
) -> Result<B1CDrivePreflightProducerPlan, B1CDrivePreflightProducerPlanFault> {
    let inputs = validate_request(request)?;
    let preparation = &inputs.preparation_request;
    let candidate = &preparation.candidate_root;
    let allowed = format!("{candidate}\\{SENTINEL_ROOT}\\allowed.txt");
    let denied = format!("{candidate}\\{SENTINEL_ROOT}\\denied.txt");
    let write_canary = format!("{candidate}\\{SENTINEL_ROOT}\\write_canary.txt");
    let filesystem_override = format!(
        "permissions.{PROFILE_ID}.filesystem={{':root'='deny',':minimal'='read','{candidate}'='read','{denied}'='deny'}}"
    );
    let children = vec![
        child(
            1,
            B1CDrivePreflightProducerChildKind::Version,
            vec!["--version".to_owned()],
            &preparation.scratch_root,
            false,
        ),
        child(
            2,
            B1CDrivePreflightProducerChildKind::StandardSchema,
            vec![
                "app-server".to_owned(),
                "generate-json-schema".to_owned(),
                "--out".to_owned(),
                format!("{}\\standard-schema", preparation.temp_root),
            ],
            &preparation.scratch_root,
            false,
        ),
        child(
            3,
            B1CDrivePreflightProducerChildKind::ExperimentalSchema,
            vec![
                "app-server".to_owned(),
                "generate-json-schema".to_owned(),
                "--experimental".to_owned(),
                "--out".to_owned(),
                format!("{}\\experimental-schema", preparation.temp_root),
            ],
            &preparation.scratch_root,
            false,
        ),
        child(
            4,
            B1CDrivePreflightProducerChildKind::AppServer,
            vec![
                "app-server".to_owned(),
                "--strict-config".to_owned(),
                "-c".to_owned(),
                format!("default_permissions=\"{PROFILE_ID}\""),
                "-c".to_owned(),
                filesystem_override.clone(),
                "-c".to_owned(),
                format!("permissions.{PROFILE_ID}.network.enabled=false"),
                "-c".to_owned(),
                "analytics.enabled=false".to_owned(),
            ],
            candidate,
            true,
        ),
    ];
    let outbound_frames = vec![
        json!({"method":"initialize","id":0,"params":{"clientInfo":{"name":"cantor_swa05_b1_preflight","title":"Cantor SWA-05 B1 Preflight","version":"0.2.0"},"capabilities":{"experimentalApi":true}}}),
        json!({"method":"initialized","params":{}}),
        json!({"method":"permissionProfile/list","id":1,"params":{"cwd":candidate}}),
        command_frame(
            2,
            vec![COMMAND_EXECUTABLE, "/d", "/c", "type", &allowed],
            candidate,
        ),
        command_frame(
            3,
            vec![COMMAND_EXECUTABLE, "/d", "/c", "type", &denied],
            candidate,
        ),
        command_frame(
            4,
            vec![
                COMMAND_EXECUTABLE,
                "/d",
                "/c",
                "echo",
                WRITE_SENTINEL,
                ">",
                &write_canary,
            ],
            candidate,
        ),
    ];
    let mut plan = B1CDrivePreflightProducerPlan {
        profile: B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_PROFILE.to_owned(),
        status: B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_STATUS.to_owned(),
        authority: B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_AUTHORITY.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PREFLIGHT_PRODUCER_SOURCE_SNAPSHOT_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PREFLIGHT_PRODUCER_SIGNATURE_UUID.to_owned(),
        request_sha256: request.request_sha256.clone(),
        commission_admission_receipt_sha256: sha256_bytes(
            request.commission_admission_receipt_machine_form.as_bytes(),
        ),
        preparation_request_sha256: sha256_bytes(
            request.preparation_request_machine_form.as_bytes(),
        ),
        preparation_filesystem_sha256: sha256_bytes(
            request.preparation_filesystem_machine_form.as_bytes(),
        ),
        preparation_git_sha256: sha256_bytes(request.preparation_git_machine_form.as_bytes()),
        preparation_outcome_sha256: sha256_bytes(
            request.preparation_outcome_machine_form.as_bytes(),
        ),
        selected_executable: B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE.to_owned(),
        selected_executable_bytes: B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE_BYTES,
        selected_executable_sha256: B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE_SHA256
            .to_owned(),
        selected_executable_version: "codex-cli 0.135.0".to_owned(),
        standard_schema_sha256: B1_CDRIVE_PREFLIGHT_PRODUCER_STANDARD_SCHEMA_SHA256.to_owned(),
        experimental_schema_sha256: B1_CDRIVE_PREFLIGHT_PRODUCER_EXPERIMENTAL_SCHEMA_SHA256
            .to_owned(),
        permission_profile_id: PROFILE_ID.to_owned(),
        filesystem_override,
        network_enabled: false,
        environment: request.environment.clone(),
        denied_environment: DENIED_ENVIRONMENT_NAMES.map(str::to_owned).to_vec(),
        children,
        outbound_frames,
        expected_incoming_frame_count: 6,
        expected_total_transcript_frame_count: 12,
        evidence_artifact_names: EVIDENCE_ARTIFACT_NAMES.map(str::to_owned).to_vec(),
        maximum_inventory_entries: 8_192,
        maximum_process_count: 4,
        physical_execution_authorized: false,
        physical_run_count: 0,
        provider_trial_count: 0,
        model_turn_count: 0,
        mcp_call_count: 0,
        network_contact_count: 0,
        d_drive_contact_count: 0,
        cleanup_count: 0,
        next_required_authorities: NEXT_REQUIRED_AUTHORITIES.map(str::to_owned).to_vec(),
        plan_sha256: empty_digest(),
    };
    plan.plan_sha256 = producer_plan_digest(&plan)?;
    validate_plan_shape(&plan, &inputs.commission_receipt)?;
    Ok(plan)
}

pub fn validate_b1_cdrive_preflight_producer_plan(
    request: &B1CDrivePreflightProducerPlanRequest,
    plan: &B1CDrivePreflightProducerPlan,
) -> Result<(), B1CDrivePreflightProducerPlanFault> {
    let expected = compile_b1_cdrive_preflight_producer_plan(request)?;
    if &expected != plan {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::Plan,
            "producer plan differs from the exact compiled plan",
        ));
    }
    Ok(())
}

pub fn to_b1_cdrive_preflight_producer_plan_request_machine_form(
    request: &B1CDrivePreflightProducerPlanRequest,
) -> Result<String, B1CDrivePreflightProducerPlanFault> {
    validate_request(request)?;
    serialize_bounded(request)
}

pub fn from_b1_cdrive_preflight_producer_plan_request_machine_form(
    value: &str,
) -> Result<B1CDrivePreflightProducerPlanRequest, B1CDrivePreflightProducerPlanFault> {
    let request: B1CDrivePreflightProducerPlanRequest = parse_strict_bounded(value)?;
    validate_request(&request)?;
    if serialize_bounded(&request)? != value {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::MachineForm,
            "producer plan request is not canonical compact JSON",
        ));
    }
    Ok(request)
}

pub fn to_b1_cdrive_preflight_producer_plan_machine_form(
    request: &B1CDrivePreflightProducerPlanRequest,
    plan: &B1CDrivePreflightProducerPlan,
) -> Result<String, B1CDrivePreflightProducerPlanFault> {
    validate_b1_cdrive_preflight_producer_plan(request, plan)?;
    serialize_bounded(plan)
}

pub fn from_b1_cdrive_preflight_producer_plan_machine_form(
    request: &B1CDrivePreflightProducerPlanRequest,
    value: &str,
) -> Result<B1CDrivePreflightProducerPlan, B1CDrivePreflightProducerPlanFault> {
    let plan: B1CDrivePreflightProducerPlan = parse_strict_bounded(value)?;
    validate_b1_cdrive_preflight_producer_plan(request, &plan)?;
    if serialize_bounded(&plan)? != value {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::MachineForm,
            "producer plan is not canonical compact JSON",
        ));
    }
    Ok(plan)
}

pub fn b1_cdrive_preflight_producer_plan_request_digest(
    request: &B1CDrivePreflightProducerPlanRequest,
) -> Result<ContentDigest, B1CDrivePreflightProducerPlanFault> {
    let mut normalized = request.clone();
    normalized.request_sha256 = empty_digest();
    domain_digest(REQUEST_DOMAIN, &normalized)
}

pub fn producer_plan_digest(
    plan: &B1CDrivePreflightProducerPlan,
) -> Result<ContentDigest, B1CDrivePreflightProducerPlanFault> {
    let mut normalized = plan.clone();
    normalized.plan_sha256 = empty_digest();
    domain_digest(PLAN_DOMAIN, &normalized)
}

struct ValidatedInputs {
    commission_receipt: PreparationCommissionAdmissionReceipt,
    preparation_request: CDriveWorktreePreparationRequest,
}

fn validate_request(
    request: &B1CDrivePreflightProducerPlanRequest,
) -> Result<ValidatedInputs, B1CDrivePreflightProducerPlanFault> {
    if request.profile != B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_REQUEST_PROFILE
        || request.source_snapshot_uuid != B1_CDRIVE_PREFLIGHT_PRODUCER_SOURCE_SNAPSHOT_UUID
        || request.signature_uuid != B1_CDRIVE_PREFLIGHT_PRODUCER_SIGNATURE_UUID
    {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::Lineage,
            "producer plan request lineage differs",
        ));
    }
    if request.request_sha256 != b1_cdrive_preflight_producer_plan_request_digest(request)? {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::Digest,
            "producer plan request self-digest differs",
        ));
    }
    validate_environment(&request.environment)?;
    let commission_receipt = from_preparation_commission_admission_receipt_machine_form(
        &request.commission_admission_receipt_machine_form,
    )
    .map_err(|error| commission_fault(error.to_string()))?;
    if to_preparation_commission_admission_receipt_machine_form(&commission_receipt)
        .map_err(|error| commission_fault(error.to_string()))?
        != request.commission_admission_receipt_machine_form
    {
        return Err(commission_fault(
            "commission admission receipt is not canonical compact JSON",
        ));
    }
    let preparation_request = from_cdrive_worktree_preparation_request_machine_form(
        &request.preparation_request_machine_form,
    )
    .map_err(|error| preparation_fault(error.to_string()))?;
    let filesystem: PreparationFilesystemObservation =
        from_cdrive_worktree_preparation_filesystem_machine_form(
            &request.preparation_filesystem_machine_form,
        )
        .map_err(|error| preparation_fault(error.to_string()))?;
    let git: PreparationGitObservation =
        from_cdrive_worktree_preparation_git_observation_machine_form(
            &request.preparation_git_machine_form,
        )
        .map_err(|error| preparation_fault(error.to_string()))?;
    let outcome: PreparationOutcomeAccount = from_cdrive_worktree_preparation_outcome_machine_form(
        &preparation_request,
        &request.preparation_outcome_machine_form,
    )
    .map_err(|error| preparation_fault(error.to_string()))?;
    validate_canonical_nested(
        &request.preparation_request_machine_form,
        &preparation_request,
        "preparation request",
    )?;
    validate_canonical_nested(
        &request.preparation_filesystem_machine_form,
        &filesystem,
        "preparation filesystem",
    )?;
    validate_canonical_nested(
        &request.preparation_git_machine_form,
        &git,
        "preparation Git observation",
    )?;
    validate_canonical_nested(
        &request.preparation_outcome_machine_form,
        &outcome,
        "preparation outcome",
    )?;
    validate_cdrive_worktree_prepared_observations(
        &preparation_request,
        &filesystem,
        &git,
        &outcome,
    )
    .map_err(|error| preparation_fault(error.to_string()))?;
    if outcome.disposition != PreparationOutcomeDisposition::PreparedForPhase3aAcquisition {
        return Err(preparation_fault(
            "preparation is not retained and verified",
        ));
    }
    Ok(ValidatedInputs {
        commission_receipt,
        preparation_request,
    })
}

fn validate_environment(
    environment: &[B1CDrivePreflightProducerEnvironmentValue],
) -> Result<(), B1CDrivePreflightProducerPlanFault> {
    if environment.len() != ENVIRONMENT_NAMES.len() {
        return Err(environment_fault("environment count differs"));
    }
    for (entry, expected) in environment.iter().zip(ENVIRONMENT_NAMES) {
        if entry.name != expected
            || entry.value.is_empty()
            || entry.value.len() > 4_096
            || entry.value.contains(['\0', '\r', '\n'])
            || entry.value.to_ascii_uppercase().contains("D:\\")
        {
            return Err(environment_fault("environment coordinate differs"));
        }
    }
    if environment[1].value != "C:\\Windows\\System32;C:\\Windows"
        || environment[2].value != ".COM;.EXE;.BAT;.CMD"
        || environment[3].value != "C:\\Windows"
        || environment[6].value != "C:\\Windows"
        || environment[4].value != environment[5].value
    {
        return Err(environment_fault("closed Windows environment differs"));
    }
    Ok(())
}

fn validate_plan_shape(
    plan: &B1CDrivePreflightProducerPlan,
    commission: &PreparationCommissionAdmissionReceipt,
) -> Result<(), B1CDrivePreflightProducerPlanFault> {
    if plan.profile != B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_PROFILE
        || plan.status != B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_STATUS
        || plan.authority != B1_CDRIVE_PREFLIGHT_PRODUCER_PLAN_AUTHORITY
        || commission.status
            != PreparationCommissionAdmissionStatus::CommissionShapeAdmittedProductionBrokerNotRun
        || commission.authority != PreparationCommissionAdmissionAuthority::CommissionAdmissionOnly
        || commission.physical_execution_authorized
        || commission.production_broker_implemented
        || commission.production_broker_run
        || commission.authorization_authenticated
        || commission.operator_consent_observed
        || commission.exclusive_lease_acquired
        || commission.consumption_ledger_claimed
        || plan.children.len() != 4
        || plan.outbound_frames.len() != 6
        || plan.expected_incoming_frame_count != 6
        || plan.expected_total_transcript_frame_count != 12
        || plan.evidence_artifact_names != EVIDENCE_ARTIFACT_NAMES.map(str::to_owned)
        || plan.maximum_inventory_entries != 8_192
        || plan.maximum_process_count != 4
        || plan.physical_execution_authorized
        || plan.physical_run_count != 0
        || plan.provider_trial_count != 0
        || plan.model_turn_count != 0
        || plan.mcp_call_count != 0
        || plan.network_contact_count != 0
        || plan.d_drive_contact_count != 0
        || plan.cleanup_count != 0
        || plan.next_required_authorities != NEXT_REQUIRED_AUTHORITIES.map(str::to_owned)
        || plan.plan_sha256 != producer_plan_digest(plan)?
    {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::Plan,
            "producer plan authority shape or self-digest differs",
        ));
    }
    Ok(())
}

fn child(
    sequence: u8,
    kind: B1CDrivePreflightProducerChildKind,
    arguments: Vec<String>,
    working_directory: &str,
    stdin_jsonl: bool,
) -> B1CDrivePreflightProducerChildSpec {
    B1CDrivePreflightProducerChildSpec {
        sequence,
        kind,
        executable: B1_CDRIVE_PREFLIGHT_PRODUCER_SELECTED_EXECUTABLE.to_owned(),
        arguments,
        working_directory: working_directory.to_owned(),
        environment_clear_first: true,
        stdin_jsonl,
        maximum_stdout_bytes: 16 * 1024 * 1024,
        maximum_stderr_bytes: 2 * 1024 * 1024,
        timeout_millis: 30_000,
        terminate_on_timeout: true,
        wait_after_terminate: true,
        require_descendant_free: true,
        require_late_output_free: true,
    }
}

fn command_frame(id: u64, command: Vec<&str>, candidate: &str) -> Value {
    json!({"method":"command/exec","id":id,"params":{"command":command,"cwd":candidate,"permissionProfile":PROFILE_ID,"timeoutMs":10000,"disableOutputCap":false}})
}

fn validate_canonical_nested(
    machine_form: &str,
    value: &impl Serialize,
    name: &str,
) -> Result<(), B1CDrivePreflightProducerPlanFault> {
    let canonical = serde_json::to_string(value).map_err(machine_fault)?;
    if canonical != machine_form {
        return Err(preparation_fault(format!(
            "{name} is not canonical compact JSON"
        )));
    }
    Ok(())
}

fn domain_digest(
    domain: &str,
    value: &impl Serialize,
) -> Result<ContentDigest, B1CDrivePreflightProducerPlanFault> {
    let payload = serde_json::to_vec(value).map_err(machine_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + payload.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&payload);
    Ok(sha256_bytes(&bytes))
}

fn serialize_bounded(value: &impl Serialize) -> Result<String, B1CDrivePreflightProducerPlanFault> {
    let machine_form = serde_json::to_string(value).map_err(machine_fault)?;
    if machine_form.len() > B1_CDRIVE_PREFLIGHT_PRODUCER_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::Bound,
            "producer machine form exceeds byte bound",
        ));
    }
    Ok(machine_form)
}

fn parse_strict_bounded<T: DeserializeOwned>(
    value: &str,
) -> Result<T, B1CDrivePreflightProducerPlanFault> {
    if value.len() > B1_CDRIVE_PREFLIGHT_PRODUCER_MAX_MACHINE_FORM_BYTES {
        return Err(fault(
            B1CDrivePreflightProducerPlanFaultCode::Bound,
            "producer machine form exceeds byte bound",
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
    code: B1CDrivePreflightProducerPlanFaultCode,
    message: impl Into<String>,
) -> B1CDrivePreflightProducerPlanFault {
    B1CDrivePreflightProducerPlanFault {
        code,
        message: message.into(),
    }
}

fn machine_fault(error: impl fmt::Display) -> B1CDrivePreflightProducerPlanFault {
    fault(
        B1CDrivePreflightProducerPlanFaultCode::MachineForm,
        error.to_string(),
    )
}

fn commission_fault(message: impl Into<String>) -> B1CDrivePreflightProducerPlanFault {
    fault(B1CDrivePreflightProducerPlanFaultCode::Commission, message)
}

fn preparation_fault(message: impl Into<String>) -> B1CDrivePreflightProducerPlanFault {
    fault(B1CDrivePreflightProducerPlanFaultCode::Preparation, message)
}

fn environment_fault(message: impl Into<String>) -> B1CDrivePreflightProducerPlanFault {
    fault(B1CDrivePreflightProducerPlanFaultCode::Environment, message)
}
