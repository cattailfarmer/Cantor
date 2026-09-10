use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const EVOX2_SCRATCH_BUILD_CONTROLLER_REQUEST_PROFILE: &str =
    "cantor-evox2-scratch-build-deployment-controller-request/0.1";
pub const EVOX2_SCRATCH_BUILD_CONTROLLER_PLAN_PROFILE: &str =
    "cantor-evox2-scratch-build-deployment-controller-plan/0.1";
pub const EVOX2_SCRATCH_BUILD_CONTROLLER_VERIFICATION_PROFILE: &str =
    "cantor-evox2-scratch-build-deployment-controller-verification/0.1";
pub const EVOX2_SCRATCH_BUILD_CONTROLLER_CANONICAL_UUID: &str =
    "935e020f-8c6f-49e4-b355-63eabd3b778b";
pub const EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_EVIDENCE_COMMIT: &str =
    "4dc154234cd88c192495126a4374d74616ca0c3f";
pub const EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_EVIDENCE_BOOKEND_COMMIT: &str =
    "9e583948ea6c1f52604862c354e99d8ccb1195ba";
pub const EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_IMPLEMENTATION_COMMIT: &str =
    "f5b904fc8cf48b34672dead0596e9de6e706f38b";
pub const EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_SET_SHA256: &str =
    "fed126ed060edfc3bccb0d3d7e6ed7dd27048a976753b5c2e23c0da45511030e";

const REQUEST_DIGEST_DOMAIN: &str = "cantor-evox2-scratch-build-deployment-controller-request-v1";
const PLAN_DIGEST_DOMAIN: &str = "cantor-evox2-scratch-build-deployment-controller-plan-v1";
const MAXIMUM_MACHINE_BYTES: usize = 65_536;
const TARGET_HOST: &str = "EVO-X2";
const SSH_HOST: &str = "evo-x2";
const PACKAGE_ROOT: &str = "D:/CantorBuilds/evox2-scratch-build-executor-p0-package-f5b904fc";
const LOCAL_EVIDENCE_PARENT: &str = "D:/CantorBuilds";
const REMOTE_SERVICE_ROOT: &str = "C:/AI/services/cantor-scratch-build-4fdd29cb";
const REMOTE_WORKSPACE_ROOT: &str = "C:/AI/workspaces/cantor-build-4fdd29cb";
const REMOTE_TARGET_ROOT: &str = "C:/AI/builds/cantor-build-4fdd29cb";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildControllerRequest {
    pub profile: String,
    pub run_uuid: String,
    pub canonical_uuid: String,
    pub package_evidence_commit: String,
    pub package_evidence_bookend_commit: String,
    pub package_implementation_commit: String,
    pub package_set_sha256: String,
    pub controller_implementation_commit: String,
    pub controller_publication_bookend_commit: String,
    pub package_root: String,
    pub target_host: String,
    pub ssh_host: String,
    pub local_evidence_root: String,
    pub remote_transport_archive: String,
    pub remote_stage_root: String,
    pub remote_service_root: String,
    pub remote_workspace_root: String,
    pub remote_target_root: String,
    pub disposition: String,
    pub request_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildControllerStage {
    pub ordinal: u32,
    pub kind: String,
    pub required_authority: String,
    pub effectful: bool,
    pub stop_on_failure: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildControllerPlan {
    pub profile: String,
    pub run_uuid: String,
    pub canonical_uuid: String,
    pub request_sha256: String,
    pub package_evidence_commit: String,
    pub package_evidence_bookend_commit: String,
    pub package_implementation_commit: String,
    pub package_set_sha256: String,
    pub controller_implementation_commit: String,
    pub controller_publication_bookend_commit: String,
    pub package_root: String,
    pub target_host: String,
    pub ssh_host: String,
    pub local_evidence_root: String,
    pub remote_transport_archive: String,
    pub remote_stage_root: String,
    pub remote_service_root: String,
    pub remote_workspace_root: String,
    pub remote_target_root: String,
    pub stages: Vec<Evox2ScratchBuildControllerStage>,
    pub stage_count: u32,
    pub provider_unavailable_disposition: String,
    pub cleanup_condition: String,
    pub authority_disposition: String,
    pub remote_contact_authorized: bool,
    pub effects: u32,
    pub plan_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2ScratchBuildControllerVerification {
    pub profile: String,
    pub status: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub stage_count: u32,
    pub effectful_stage_count: u32,
    pub remote_contact_authorized: bool,
    pub effects: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evox2ScratchBuildControllerFaultCode {
    InvalidMachineForm,
    InvalidIdentity,
    InvalidDigest,
    InvalidPath,
    InvalidPlan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2ScratchBuildControllerFault {
    pub code: Evox2ScratchBuildControllerFaultCode,
    pub detail: &'static str,
}

impl fmt::Display for Evox2ScratchBuildControllerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Evox2ScratchBuildControllerFault {}

pub fn fixed_evox2_scratch_build_controller_request(
    run_uuid: &str,
    controller_implementation_commit: &str,
    controller_publication_bookend_commit: &str,
) -> Result<Evox2ScratchBuildControllerRequest, Evox2ScratchBuildControllerFault> {
    seal_evox2_scratch_build_controller_request(Evox2ScratchBuildControllerRequest {
        profile: EVOX2_SCRATCH_BUILD_CONTROLLER_REQUEST_PROFILE.to_owned(),
        run_uuid: run_uuid.to_owned(),
        canonical_uuid: EVOX2_SCRATCH_BUILD_CONTROLLER_CANONICAL_UUID.to_owned(),
        package_evidence_commit: EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_EVIDENCE_COMMIT.to_owned(),
        package_evidence_bookend_commit:
            EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_EVIDENCE_BOOKEND_COMMIT.to_owned(),
        package_implementation_commit: EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_IMPLEMENTATION_COMMIT
            .to_owned(),
        package_set_sha256: EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_SET_SHA256.to_owned(),
        controller_implementation_commit: controller_implementation_commit.to_owned(),
        controller_publication_bookend_commit: controller_publication_bookend_commit.to_owned(),
        package_root: PACKAGE_ROOT.to_owned(),
        target_host: TARGET_HOST.to_owned(),
        ssh_host: SSH_HOST.to_owned(),
        local_evidence_root: format!(
            "{LOCAL_EVIDENCE_PARENT}/evox2-scratch-build-executor-p0-live-{run_uuid}"
        ),
        remote_transport_archive: format!(
            "C:/AI/transport/cantor-scratch-build-transport-{run_uuid}.zip"
        ),
        remote_stage_root: format!("C:/AI/services/cantor-scratch-build-staging-{run_uuid}"),
        remote_service_root: REMOTE_SERVICE_ROOT.to_owned(),
        remote_workspace_root: REMOTE_WORKSPACE_ROOT.to_owned(),
        remote_target_root: REMOTE_TARGET_ROOT.to_owned(),
        disposition: "proposed_not_authorized".to_owned(),
        request_sha256: String::new(),
    })
}

pub fn seal_evox2_scratch_build_controller_request(
    mut request: Evox2ScratchBuildControllerRequest,
) -> Result<Evox2ScratchBuildControllerRequest, Evox2ScratchBuildControllerFault> {
    request.request_sha256.clear();
    validate_request_body(&request)?;
    request.request_sha256 = request_digest(&request)?;
    validate_evox2_scratch_build_controller_request(&request)?;
    Ok(request)
}

pub fn validate_evox2_scratch_build_controller_request(
    request: &Evox2ScratchBuildControllerRequest,
) -> Result<(), Evox2ScratchBuildControllerFault> {
    validate_request_body(request)?;
    if request.request_sha256 != request_digest(request)? {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidDigest,
            "controller request digest differs",
        ));
    }
    Ok(())
}

pub fn compile_evox2_scratch_build_controller_plan(
    request: &Evox2ScratchBuildControllerRequest,
) -> Result<Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerFault> {
    validate_evox2_scratch_build_controller_request(request)?;
    let mut plan = Evox2ScratchBuildControllerPlan {
        profile: EVOX2_SCRATCH_BUILD_CONTROLLER_PLAN_PROFILE.to_owned(),
        run_uuid: request.run_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        package_evidence_commit: request.package_evidence_commit.clone(),
        package_evidence_bookend_commit: request.package_evidence_bookend_commit.clone(),
        package_implementation_commit: request.package_implementation_commit.clone(),
        package_set_sha256: request.package_set_sha256.clone(),
        controller_implementation_commit: request.controller_implementation_commit.clone(),
        controller_publication_bookend_commit: request
            .controller_publication_bookend_commit
            .clone(),
        package_root: request.package_root.clone(),
        target_host: request.target_host.clone(),
        ssh_host: request.ssh_host.clone(),
        local_evidence_root: request.local_evidence_root.clone(),
        remote_transport_archive: request.remote_transport_archive.clone(),
        remote_stage_root: request.remote_stage_root.clone(),
        remote_service_root: request.remote_service_root.clone(),
        remote_workspace_root: request.remote_workspace_root.clone(),
        remote_target_root: request.remote_target_root.clone(),
        stages: fixed_stages(),
        stage_count: 10,
        provider_unavailable_disposition: "operational_refusal_before_commission_no_receipt"
            .to_owned(),
        cleanup_condition: "transient_transport_only_after_local_evidence_verification".to_owned(),
        authority_disposition: "descriptive_not_authorizing".to_owned(),
        remote_contact_authorized: false,
        effects: 0,
        plan_sha256: String::new(),
    };
    plan.plan_sha256 = plan_digest(&plan)?;
    verify_evox2_scratch_build_controller_plan(request, &plan)?;
    Ok(plan)
}

pub fn verify_evox2_scratch_build_controller_plan(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
) -> Result<Evox2ScratchBuildControllerVerification, Evox2ScratchBuildControllerFault> {
    validate_evox2_scratch_build_controller_request(request)?;
    let expected = compile_plan_body(request);
    if plan != &expected || plan.plan_sha256 != plan_digest(plan)? {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidPlan,
            "controller plan correspondence differs",
        ));
    }
    Ok(Evox2ScratchBuildControllerVerification {
        profile: EVOX2_SCRATCH_BUILD_CONTROLLER_VERIFICATION_PROFILE.to_owned(),
        status: "passed".to_owned(),
        request_sha256: request.request_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        stage_count: plan.stage_count,
        effectful_stage_count: plan.stages.iter().filter(|stage| stage.effectful).count() as u32,
        remote_contact_authorized: false,
        effects: 0,
    })
}

pub fn to_evox2_scratch_build_controller_request_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
) -> Result<String, Evox2ScratchBuildControllerFault> {
    validate_evox2_scratch_build_controller_request(request)?;
    serialize_bounded(request)
}

pub fn from_evox2_scratch_build_controller_request_machine_form(
    value: &str,
) -> Result<Evox2ScratchBuildControllerRequest, Evox2ScratchBuildControllerFault> {
    let request = strict_deserialize(value)?;
    validate_evox2_scratch_build_controller_request(&request)?;
    Ok(request)
}

pub fn to_evox2_scratch_build_controller_plan_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    plan: &Evox2ScratchBuildControllerPlan,
) -> Result<String, Evox2ScratchBuildControllerFault> {
    verify_evox2_scratch_build_controller_plan(request, plan)?;
    serialize_bounded(plan)
}

pub fn from_evox2_scratch_build_controller_plan_machine_form(
    request: &Evox2ScratchBuildControllerRequest,
    value: &str,
) -> Result<Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerFault> {
    let plan = strict_deserialize(value)?;
    verify_evox2_scratch_build_controller_plan(request, &plan)?;
    Ok(plan)
}

pub fn to_evox2_scratch_build_controller_verification_machine_form(
    verification: &Evox2ScratchBuildControllerVerification,
) -> Result<String, Evox2ScratchBuildControllerFault> {
    if verification.profile != EVOX2_SCRATCH_BUILD_CONTROLLER_VERIFICATION_PROFILE
        || verification.status != "passed"
        || !is_lower_hex(&verification.request_sha256, 64)
        || !is_lower_hex(&verification.plan_sha256, 64)
        || verification.stage_count != 10
        || verification.effectful_stage_count != 7
        || verification.remote_contact_authorized
        || verification.effects != 0
    {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidPlan,
            "controller verification differs",
        ));
    }
    serialize_bounded(verification)
}

fn compile_plan_body(
    request: &Evox2ScratchBuildControllerRequest,
) -> Evox2ScratchBuildControllerPlan {
    let mut plan = Evox2ScratchBuildControllerPlan {
        profile: EVOX2_SCRATCH_BUILD_CONTROLLER_PLAN_PROFILE.to_owned(),
        run_uuid: request.run_uuid.clone(),
        canonical_uuid: request.canonical_uuid.clone(),
        request_sha256: request.request_sha256.clone(),
        package_evidence_commit: request.package_evidence_commit.clone(),
        package_evidence_bookend_commit: request.package_evidence_bookend_commit.clone(),
        package_implementation_commit: request.package_implementation_commit.clone(),
        package_set_sha256: request.package_set_sha256.clone(),
        controller_implementation_commit: request.controller_implementation_commit.clone(),
        controller_publication_bookend_commit: request
            .controller_publication_bookend_commit
            .clone(),
        package_root: request.package_root.clone(),
        target_host: request.target_host.clone(),
        ssh_host: request.ssh_host.clone(),
        local_evidence_root: request.local_evidence_root.clone(),
        remote_transport_archive: request.remote_transport_archive.clone(),
        remote_stage_root: request.remote_stage_root.clone(),
        remote_service_root: request.remote_service_root.clone(),
        remote_workspace_root: request.remote_workspace_root.clone(),
        remote_target_root: request.remote_target_root.clone(),
        stages: fixed_stages(),
        stage_count: 10,
        provider_unavailable_disposition: "operational_refusal_before_commission_no_receipt"
            .to_owned(),
        cleanup_condition: "transient_transport_only_after_local_evidence_verification".to_owned(),
        authority_disposition: "descriptive_not_authorizing".to_owned(),
        remote_contact_authorized: false,
        effects: 0,
        plan_sha256: String::new(),
    };
    plan.plan_sha256 = plan_digest(&plan).expect("fixed controller plan is serializable");
    plan
}

fn fixed_stages() -> Vec<Evox2ScratchBuildControllerStage> {
    [
        (1, "local_package_verify", "none", false),
        (2, "publication_lineage_verify", "none", false),
        (3, "remote_preflight", "separate_live_commission", true),
        (4, "transfer_package", "commission:source_transfer", true),
        (
            5,
            "remote_package_verify",
            "commission:source_transfer",
            true,
        ),
        (
            6,
            "atomic_service_install",
            "commission:source_extract",
            true,
        ),
        (
            7,
            "execute_commission_once",
            "commission:process_execute",
            true,
        ),
        (8, "retrieve_evidence", "commission:source_transfer", true),
        (9, "independent_local_verify", "none", false),
        (
            10,
            "cleanup_transient_transport",
            "specification:ESBE-030",
            true,
        ),
    ]
    .into_iter()
    .map(
        |(ordinal, kind, required_authority, effectful)| Evox2ScratchBuildControllerStage {
            ordinal,
            kind: kind.to_owned(),
            required_authority: required_authority.to_owned(),
            effectful,
            stop_on_failure: true,
        },
    )
    .collect()
}

fn validate_request_body(
    request: &Evox2ScratchBuildControllerRequest,
) -> Result<(), Evox2ScratchBuildControllerFault> {
    if request.profile != EVOX2_SCRATCH_BUILD_CONTROLLER_REQUEST_PROFILE
        || request.canonical_uuid != EVOX2_SCRATCH_BUILD_CONTROLLER_CANONICAL_UUID
        || request.package_evidence_commit != EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_EVIDENCE_COMMIT
        || request.package_evidence_bookend_commit
            != EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_EVIDENCE_BOOKEND_COMMIT
        || request.package_implementation_commit
            != EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_IMPLEMENTATION_COMMIT
        || request.package_set_sha256 != EVOX2_SCRATCH_BUILD_CONTROLLER_PACKAGE_SET_SHA256
        || request.target_host != TARGET_HOST
        || request.ssh_host != SSH_HOST
        || request.disposition != "proposed_not_authorized"
    {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidIdentity,
            "controller request identity differs",
        ));
    }
    if !is_uuid(&request.run_uuid)
        || !is_lower_hex(&request.controller_implementation_commit, 40)
        || !is_lower_hex(&request.controller_publication_bookend_commit, 40)
        || request.controller_implementation_commit == request.controller_publication_bookend_commit
    {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidIdentity,
            "controller publication lineage differs",
        ));
    }
    let run = &request.run_uuid;
    if request.package_root != PACKAGE_ROOT
        || request.local_evidence_root
            != format!("{LOCAL_EVIDENCE_PARENT}/evox2-scratch-build-executor-p0-live-{run}")
        || request.remote_transport_archive
            != format!("C:/AI/transport/cantor-scratch-build-transport-{run}.zip")
        || request.remote_stage_root != format!("C:/AI/services/cantor-scratch-build-staging-{run}")
        || request.remote_service_root != REMOTE_SERVICE_ROOT
        || request.remote_workspace_root != REMOTE_WORKSPACE_ROOT
        || request.remote_target_root != REMOTE_TARGET_ROOT
    {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidPath,
            "controller request coordinate differs",
        ));
    }
    Ok(())
}

fn request_digest(
    request: &Evox2ScratchBuildControllerRequest,
) -> Result<String, Evox2ScratchBuildControllerFault> {
    let mut unsigned = request.clone();
    unsigned.request_sha256.clear();
    digest_json(REQUEST_DIGEST_DOMAIN, &unsigned)
}

fn plan_digest(
    plan: &Evox2ScratchBuildControllerPlan,
) -> Result<String, Evox2ScratchBuildControllerFault> {
    let mut unsigned = plan.clone();
    unsigned.plan_sha256.clear();
    digest_json(PLAN_DIGEST_DOMAIN, &unsigned)
}

fn digest_json<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, Evox2ScratchBuildControllerFault> {
    let encoded = serde_json::to_vec(value).map_err(|_| {
        fault(
            Evox2ScratchBuildControllerFaultCode::InvalidMachineForm,
            "controller form serialization failed",
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn strict_deserialize<T>(value: &str) -> Result<T, Evox2ScratchBuildControllerFault>
where
    T: DeserializeOwned + Serialize,
{
    if value.is_empty() || value.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidMachineForm,
            "controller form byte bound differs",
        ));
    }
    let parsed: T = serde_json::from_str(value).map_err(|_| {
        fault(
            Evox2ScratchBuildControllerFaultCode::InvalidMachineForm,
            "controller form decode failed",
        )
    })?;
    let canonical = serde_json::to_string(&parsed).map_err(|_| {
        fault(
            Evox2ScratchBuildControllerFaultCode::InvalidMachineForm,
            "controller form encode failed",
        )
    })?;
    if canonical != value {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidMachineForm,
            "controller form is not canonical",
        ));
    }
    Ok(parsed)
}

fn serialize_bounded<T: Serialize>(value: &T) -> Result<String, Evox2ScratchBuildControllerFault> {
    let encoded = serde_json::to_string(value).map_err(|_| {
        fault(
            Evox2ScratchBuildControllerFaultCode::InvalidMachineForm,
            "controller form encode failed",
        )
    })?;
    if encoded.len() > MAXIMUM_MACHINE_BYTES {
        return Err(fault(
            Evox2ScratchBuildControllerFaultCode::InvalidMachineForm,
            "controller form byte bound differs",
        ));
    }
    Ok(encoded)
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fault(
    code: Evox2ScratchBuildControllerFaultCode,
    detail: &'static str,
) -> Evox2ScratchBuildControllerFault {
    Evox2ScratchBuildControllerFault { code, detail }
}
