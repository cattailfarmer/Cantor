//! Pure B0 validation for the future self-work physical update broker.
//!
//! This module validates supplied metadata only. It has no runtime carrier and
//! cannot emit a receipt for any physical broker stage.

use std::{collections::HashSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_REQUEST_PROFILE: &str = "cantor-self-work-update-broker-protocol-request/0.2";
pub const PROTOCOL_RESULT_PROFILE: &str = "cantor-self-work-update-broker-formation-validation/0.2";
pub const STAGE_PLAN_PROFILE: &str = "cantor-self-work-update-broker-stage-plan/0.2";
pub const CAPABILITY_ACCOUNT_PROFILE: &str =
    "cantor-self-work-update-broker-capability-account/0.2";
pub const SYNTHETIC_EVIDENCE_PROFILE: &str =
    "cantor-self-work-update-broker-synthetic-evidence/0.2";

const CORRECTIVE_SOURCE_SNAPSHOT_UUID: &str = "82356753-0666-41cd-9b04-cd488b4bb727";
const FORMATION_CANONICAL_UUID: &str = "88753bbf-33a0-450a-a218-d58fcf601d7d";
const FORMATION_SIGNATURE_UUID: &str = "e588644d-4420-44f6-a622-85430626bd09";
const PROTOCOL_CANONICAL_UUID: &str = "459f30e4-6c0d-4731-90b9-bfa6bdca1b61";
const PUBLISHED_PREDECESSOR: &str = "e5bee5e2e60dc2df756da8e26385fce048dc29a1";
const MAX_REQUEST_BYTES: usize = 262_144;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_PATHS: usize = 64;
const MAX_EVIDENCE: usize = 16;
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const NONAUTHORITY: &str = "protocol validation grants no physical stage implementation acceptance rollback cleanup publication or activation authority";

const ROOT_DOMAIN: &[u8] = b"cantor:self-work-update-broker:root:0.2";
const PLAN_DOMAIN: &[u8] = b"cantor:self-work-update-broker:stage-plan:0.2";
const CAPABILITY_DOMAIN: &[u8] = b"cantor:self-work-update-broker:capability-account:0.2";
const EVIDENCE_DOMAIN: &[u8] = b"cantor:self-work-update-broker:evidence-set:0.2";
const UNRESOLVED_DOMAIN: &[u8] = b"cantor:self-work-update-broker:unresolved:0.2";
const REQUEST_DOMAIN: &[u8] = b"cantor:self-work-update-broker:request:0.2";
const RESULT_DOMAIN: &[u8] = b"cantor:self-work-update-broker:result:0.2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    ReadObservation,
    EvidenceRootWrite,
    CandidateMutation,
    ProcessLaunch,
    ProcessInterrupt,
    ProcessTerminate,
    SupervisorTest,
    IndependentReview,
    RollbackAttempt,
    Cleanup,
    GitHistory,
    Commit,
    Push,
    Provider,
    SopAuthorship,
    SemanticSignature,
    Activation,
    Persistence,
    Remote,
    Fpga,
    Minecraft,
    PrincipalWorkspaceMutation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAccount {
    pub profile: String,
    pub granted: Vec<CapabilityKind>,
    pub explicitly_not_granted: Vec<CapabilityKind>,
    pub capability_account_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageKind {
    B0Protocol,
    B1HostPreflight,
    B2BoundedWriter,
    B3PostStateEvidence,
    B4IndependentReview,
    B5RollbackReobservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageDefinition {
    pub ordinal: u8,
    pub kind: StageKind,
    pub input_profile: String,
    pub output_profile: String,
    pub physical_contact_expected: bool,
    pub activation_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagePlan {
    pub profile: String,
    pub stages: Vec<StageDefinition>,
    pub stage_plan_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRoot {
    pub broker_uuid: String,
    pub correlation_uuid: String,
    pub corrective_source_snapshot_uuid: String,
    pub formation_canonical_uuid: String,
    pub formation_signature_uuid: String,
    pub protocol_canonical_uuid: String,
    pub published_predecessor_commit: String,
    pub lifecycle_request_sha256: String,
    pub checkpoint_sha256: String,
    pub step_uuid: String,
    pub attempt_uuid: String,
    pub objective_sha256: String,
    pub handoff_request_sha256: String,
    pub handoff_proposal_sha256: String,
    pub workspace_correlation_uuid: String,
    pub base_commit: String,
    pub branch_ref: String,
    pub git_executable_sha256: String,
    pub allowed_relative_paths: Vec<String>,
    pub change_set_sha256: String,
    pub broker_root_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticEvidenceRef {
    pub label: String,
    pub profile: String,
    pub sha256: String,
    pub bytes: u64,
    pub physical_contact: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolFormationRequest {
    pub profile: String,
    pub root: BrokerRoot,
    pub stage_plan: StagePlan,
    pub capability_account: CapabilityAccount,
    pub evidence: Vec<SyntheticEvidenceRef>,
    pub evidence_set_sha256: String,
    pub unresolved_frontier: Vec<String>,
    pub unresolved_frontier_sha256: String,
    pub request_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormationAuthority {
    FormationOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormationDisposition {
    FormationValidated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormationValidationRecord {
    pub profile: String,
    pub request_sha256: String,
    pub broker_uuid: String,
    pub correlation_uuid: String,
    pub stage_plan_sha256: String,
    pub capability_account_sha256: String,
    pub evidence_set_sha256: String,
    pub unresolved_frontier_sha256: String,
    pub physical_contact: bool,
    pub authority: FormationAuthority,
    pub disposition: FormationDisposition,
    pub nonauthority: String,
    pub result_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolFaultCode {
    Profile,
    Generation,
    Identity,
    Lineage,
    Path,
    StagePlan,
    Capability,
    Evidence,
    Unresolved,
    Digest,
    Authority,
    Serialization,
    Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolFault {
    pub code: ProtocolFaultCode,
    pub message: String,
}

impl fmt::Display for ProtocolFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolFault {}

pub fn compile_self_work_update_broker_protocol(
    request: &ProtocolFormationRequest,
) -> Result<FormationValidationRecord, ProtocolFault> {
    validate_self_work_update_broker_protocol_request(request)?;
    let mut result = FormationValidationRecord {
        profile: PROTOCOL_RESULT_PROFILE.to_owned(),
        request_sha256: request.request_sha256.clone(),
        broker_uuid: request.root.broker_uuid.clone(),
        correlation_uuid: request.root.correlation_uuid.clone(),
        stage_plan_sha256: request.stage_plan.stage_plan_sha256.clone(),
        capability_account_sha256: request.capability_account.capability_account_sha256.clone(),
        evidence_set_sha256: request.evidence_set_sha256.clone(),
        unresolved_frontier_sha256: request.unresolved_frontier_sha256.clone(),
        physical_contact: false,
        authority: FormationAuthority::FormationOnly,
        disposition: FormationDisposition::FormationValidated,
        nonauthority: NONAUTHORITY.to_owned(),
        result_sha256: String::new(),
    };
    result.result_sha256 = digest_form(RESULT_DOMAIN, &result)?;
    Ok(result)
}

pub fn validate_self_work_update_broker_protocol_request(
    request: &ProtocolFormationRequest,
) -> Result<(), ProtocolFault> {
    if request.profile != PROTOCOL_REQUEST_PROFILE {
        return fault(ProtocolFaultCode::Profile, "request profile differs");
    }
    validate_root(&request.root)?;
    validate_stage_plan(&request.stage_plan)?;
    validate_capability_account(&request.capability_account)?;
    validate_evidence(&request.evidence, &request.evidence_set_sha256)?;
    validate_unresolved(
        &request.unresolved_frontier,
        &request.unresolved_frontier_sha256,
    )?;
    let encoded = serde_json::to_vec(request)
        .map_err(|error| protocol_error(ProtocolFaultCode::Serialization, error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return fault(ProtocolFaultCode::Resource, "request byte bound exceeded");
    }
    let mut body = request.clone();
    body.request_sha256.clear();
    let expected = digest_form(REQUEST_DOMAIN, &body)?;
    if request.request_sha256 != expected {
        return fault(ProtocolFaultCode::Digest, "request digest differs");
    }
    Ok(())
}

pub fn validate_self_work_update_broker_protocol_result(
    request: &ProtocolFormationRequest,
    result: &FormationValidationRecord,
) -> Result<(), ProtocolFault> {
    let expected = compile_self_work_update_broker_protocol(request)?;
    if result != &expected {
        return fault(ProtocolFaultCode::Authority, "result replay differs");
    }
    Ok(())
}

pub fn protocol_request_digest(
    request: &ProtocolFormationRequest,
) -> Result<String, ProtocolFault> {
    let mut body = request.clone();
    body.request_sha256.clear();
    digest_form(REQUEST_DOMAIN, &body)
}

pub fn protocol_result_digest(result: &FormationValidationRecord) -> Result<String, ProtocolFault> {
    let mut body = result.clone();
    body.result_sha256.clear();
    digest_form(RESULT_DOMAIN, &body)
}

pub fn to_protocol_request_machine_form(
    request: &ProtocolFormationRequest,
) -> Result<Vec<u8>, ProtocolFault> {
    validate_self_work_update_broker_protocol_request(request)?;
    serde_json::to_vec(request)
        .map_err(|error| protocol_error(ProtocolFaultCode::Serialization, error.to_string()))
}

pub fn from_protocol_request_machine_form(
    bytes: &[u8],
) -> Result<ProtocolFormationRequest, ProtocolFault> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return fault(ProtocolFaultCode::Resource, "request byte bound exceeded");
    }
    let request: ProtocolFormationRequest = serde_json::from_slice(bytes)
        .map_err(|error| protocol_error(ProtocolFaultCode::Serialization, error.to_string()))?;
    validate_self_work_update_broker_protocol_request(&request)?;
    Ok(request)
}

pub fn to_protocol_result_machine_form(
    request: &ProtocolFormationRequest,
    result: &FormationValidationRecord,
) -> Result<Vec<u8>, ProtocolFault> {
    validate_self_work_update_broker_protocol_result(request, result)?;
    serde_json::to_vec(result)
        .map_err(|error| protocol_error(ProtocolFaultCode::Serialization, error.to_string()))
}

pub fn from_protocol_result_machine_form(
    request: &ProtocolFormationRequest,
    bytes: &[u8],
) -> Result<FormationValidationRecord, ProtocolFault> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return fault(ProtocolFaultCode::Resource, "result byte bound exceeded");
    }
    let result: FormationValidationRecord = serde_json::from_slice(bytes)
        .map_err(|error| protocol_error(ProtocolFaultCode::Serialization, error.to_string()))?;
    validate_self_work_update_broker_protocol_result(request, &result)?;
    Ok(result)
}

fn validate_root(root: &BrokerRoot) -> Result<(), ProtocolFault> {
    for value in [
        &root.broker_uuid,
        &root.correlation_uuid,
        &root.step_uuid,
        &root.attempt_uuid,
        &root.workspace_correlation_uuid,
    ] {
        if !is_uuid(value) {
            return fault(ProtocolFaultCode::Identity, "UUID is not canonical");
        }
    }
    if root.corrective_source_snapshot_uuid != CORRECTIVE_SOURCE_SNAPSHOT_UUID
        || root.formation_canonical_uuid != FORMATION_CANONICAL_UUID
        || root.formation_signature_uuid != FORMATION_SIGNATURE_UUID
        || root.protocol_canonical_uuid != PROTOCOL_CANONICAL_UUID
        || root.published_predecessor_commit != PUBLISHED_PREDECESSOR
    {
        return fault(ProtocolFaultCode::Generation, "generation binding differs");
    }
    for value in [
        &root.lifecycle_request_sha256,
        &root.checkpoint_sha256,
        &root.objective_sha256,
        &root.handoff_request_sha256,
        &root.handoff_proposal_sha256,
        &root.git_executable_sha256,
        &root.change_set_sha256,
    ] {
        if !is_sha256(value) {
            return fault(
                ProtocolFaultCode::Lineage,
                "lineage digest is not canonical",
            );
        }
    }
    if !is_commit(&root.base_commit)
        || root.branch_ref.len() > MAX_TEXT_BYTES
        || !root.branch_ref.starts_with("refs/heads/")
        || root.branch_ref.as_bytes().contains(&0)
    {
        return fault(ProtocolFaultCode::Lineage, "repository lineage differs");
    }
    validate_paths(&root.allowed_relative_paths)?;
    let mut body = root.clone();
    body.broker_root_sha256.clear();
    if root.broker_root_sha256 != digest_form(ROOT_DOMAIN, &body)? {
        return fault(ProtocolFaultCode::Digest, "broker root digest differs");
    }
    Ok(())
}

fn validate_stage_plan(plan: &StagePlan) -> Result<(), ProtocolFault> {
    if plan.profile != STAGE_PLAN_PROFILE || plan.stages != expected_stages() {
        return fault(ProtocolFaultCode::StagePlan, "stage plan differs");
    }
    let mut body = plan.clone();
    body.stage_plan_sha256.clear();
    if plan.stage_plan_sha256 != digest_form(PLAN_DOMAIN, &body)? {
        return fault(ProtocolFaultCode::Digest, "stage plan digest differs");
    }
    Ok(())
}

fn validate_capability_account(account: &CapabilityAccount) -> Result<(), ProtocolFault> {
    let expected = all_capabilities();
    if expected.len() != 22
        || expected.iter().copied().collect::<HashSet<_>>().len() != 22
        || account.profile != CAPABILITY_ACCOUNT_PROFILE
        || !account.granted.is_empty()
        || account.explicitly_not_granted != expected
    {
        return fault(ProtocolFaultCode::Capability, "capability set differs");
    }
    let mut body = account.clone();
    body.capability_account_sha256.clear();
    if account.capability_account_sha256 != digest_form(CAPABILITY_DOMAIN, &body)? {
        return fault(ProtocolFaultCode::Digest, "capability digest differs");
    }
    Ok(())
}

fn validate_evidence(
    evidence: &[SyntheticEvidenceRef],
    supplied_digest: &str,
) -> Result<(), ProtocolFault> {
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE {
        return fault(ProtocolFaultCode::Resource, "evidence count differs");
    }
    let mut previous: Option<&str> = None;
    for item in evidence {
        if !valid_text(&item.label)
            || !valid_text(&item.profile)
            || !is_sha256(&item.sha256)
            || item.bytes == 0
            || item.bytes > MAX_EVIDENCE_BYTES
            || item.physical_contact
            || item.profile != SYNTHETIC_EVIDENCE_PROFILE
            || previous.is_some_and(|value| value >= item.label.as_str())
        {
            return fault(ProtocolFaultCode::Evidence, "synthetic evidence differs");
        }
        previous = Some(&item.label);
    }
    if supplied_digest != digest_form(EVIDENCE_DOMAIN, &evidence)? {
        return fault(ProtocolFaultCode::Digest, "evidence digest differs");
    }
    Ok(())
}

fn validate_unresolved(values: &[String], supplied_digest: &str) -> Result<(), ProtocolFault> {
    if values != expected_unresolved().as_slice() {
        return fault(ProtocolFaultCode::Unresolved, "activation frontier differs");
    }
    if supplied_digest != digest_form(UNRESOLVED_DOMAIN, &values)? {
        return fault(ProtocolFaultCode::Digest, "unresolved digest differs");
    }
    Ok(())
}

fn validate_paths(paths: &[String]) -> Result<(), ProtocolFault> {
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return fault(ProtocolFaultCode::Resource, "path count differs");
    }
    let mut previous: Option<&str> = None;
    for path in paths {
        let segments: Vec<&str> = path.split('/').collect();
        if path.len() > MAX_PATH_BYTES
            || path.is_empty()
            || path.starts_with('/')
            || path.ends_with('/')
            || path.contains('\\')
            || path.contains(':')
            || path.chars().any(char::is_control)
            || segments
                .iter()
                .any(|part| part.is_empty() || *part == "." || *part == "..")
            || previous.is_some_and(|value| value >= path.as_str())
        {
            return fault(ProtocolFaultCode::Path, "allowed path differs");
        }
        previous = Some(path);
    }
    Ok(())
}

fn expected_stages() -> Vec<StageDefinition> {
    vec![
        stage(
            1,
            StageKind::B0Protocol,
            PROTOCOL_REQUEST_PROFILE,
            PROTOCOL_RESULT_PROFILE,
            false,
        ),
        stage(
            2,
            StageKind::B1HostPreflight,
            "cantor-self-work-update-broker-b1-preflight-request/0.2",
            "cantor-self-work-update-broker-b1-preflight-record/0.2",
            true,
        ),
        stage(
            3,
            StageKind::B2BoundedWriter,
            "cantor-self-work-update-broker-b2-writer-request/0.2",
            "cantor-self-work-update-broker-b2-mutation-record/0.2",
            true,
        ),
        stage(
            4,
            StageKind::B3PostStateEvidence,
            "cantor-self-work-update-broker-b3-observation-request/0.2",
            "cantor-self-work-update-broker-b3-post-state-record/0.2",
            true,
        ),
        stage(
            5,
            StageKind::B4IndependentReview,
            "cantor-self-work-update-broker-b4-review-request/0.2",
            "cantor-self-work-update-broker-b4-review-record/0.2",
            true,
        ),
        stage(
            6,
            StageKind::B5RollbackReobservation,
            "cantor-self-work-update-broker-b5-rollback-request/0.2",
            "cantor-self-work-update-broker-b5-rollback-record/0.2",
            true,
        ),
    ]
}

fn stage(
    ordinal: u8,
    kind: StageKind,
    input: &str,
    output: &str,
    physical_contact_expected: bool,
) -> StageDefinition {
    StageDefinition {
        ordinal,
        kind,
        input_profile: input.to_owned(),
        output_profile: output.to_owned(),
        physical_contact_expected,
        activation_required: true,
    }
}

fn all_capabilities() -> Vec<CapabilityKind> {
    use CapabilityKind::*;
    vec![
        ReadObservation,
        EvidenceRootWrite,
        CandidateMutation,
        ProcessLaunch,
        ProcessInterrupt,
        ProcessTerminate,
        SupervisorTest,
        IndependentReview,
        RollbackAttempt,
        Cleanup,
        GitHistory,
        Commit,
        Push,
        Provider,
        SopAuthorship,
        SemanticSignature,
        Activation,
        Persistence,
        Remote,
        Fpga,
        Minecraft,
        PrincipalWorkspaceMutation,
    ]
}

fn expected_unresolved() -> Vec<String> {
    [
        "current_interface",
        "target_host_containment",
        "writer",
        "observer",
        "evidence_root",
        "reviewer",
        "rollback_executor",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn digest_form<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> Result<String, ProtocolFault> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| protocol_error(ProtocolFaultCode::Serialization, error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.as_bytes().contains(&0)
}

fn protocol_error(code: ProtocolFaultCode, message: impl Into<String>) -> ProtocolFault {
    ProtocolFault {
        code,
        message: message.into(),
    }
}

fn fault<T>(code: ProtocolFaultCode, message: impl Into<String>) -> Result<T, ProtocolFault> {
    Err(protocol_error(code, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(seed: char) -> String {
        seed.to_string().repeat(64)
    }

    fn request() -> ProtocolFormationRequest {
        let mut root = BrokerRoot {
            broker_uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
            correlation_uuid: "22222222-2222-4222-8222-222222222222".to_owned(),
            corrective_source_snapshot_uuid: CORRECTIVE_SOURCE_SNAPSHOT_UUID.to_owned(),
            formation_canonical_uuid: FORMATION_CANONICAL_UUID.to_owned(),
            formation_signature_uuid: FORMATION_SIGNATURE_UUID.to_owned(),
            protocol_canonical_uuid: PROTOCOL_CANONICAL_UUID.to_owned(),
            published_predecessor_commit: PUBLISHED_PREDECESSOR.to_owned(),
            lifecycle_request_sha256: sha('1'),
            checkpoint_sha256: sha('2'),
            step_uuid: "33333333-3333-4333-8333-333333333333".to_owned(),
            attempt_uuid: "44444444-4444-4444-8444-444444444444".to_owned(),
            objective_sha256: sha('3'),
            handoff_request_sha256: sha('4'),
            handoff_proposal_sha256: sha('5'),
            workspace_correlation_uuid: "55555555-5555-4555-8555-555555555555".to_owned(),
            base_commit: "a".repeat(40),
            branch_ref: "refs/heads/codex/self-hosted-corpus".to_owned(),
            git_executable_sha256: sha('6'),
            allowed_relative_paths: vec!["crates/cantor_ecosystem/src/example.rs".to_owned()],
            change_set_sha256: sha('7'),
            broker_root_sha256: String::new(),
        };
        root.broker_root_sha256 = digest_form(ROOT_DOMAIN, &root).unwrap();

        let mut stage_plan = StagePlan {
            profile: STAGE_PLAN_PROFILE.to_owned(),
            stages: expected_stages(),
            stage_plan_sha256: String::new(),
        };
        stage_plan.stage_plan_sha256 = digest_form(PLAN_DOMAIN, &stage_plan).unwrap();

        let mut capability_account = CapabilityAccount {
            profile: CAPABILITY_ACCOUNT_PROFILE.to_owned(),
            granted: vec![],
            explicitly_not_granted: all_capabilities(),
            capability_account_sha256: String::new(),
        };
        capability_account.capability_account_sha256 =
            digest_form(CAPABILITY_DOMAIN, &capability_account).unwrap();

        let evidence = vec![SyntheticEvidenceRef {
            label: "fixture:complete_plan".to_owned(),
            profile: SYNTHETIC_EVIDENCE_PROFILE.to_owned(),
            sha256: sha('8'),
            bytes: 128,
            physical_contact: false,
        }];
        let evidence_set_sha256 = digest_form(EVIDENCE_DOMAIN, &evidence).unwrap();
        let unresolved_frontier = expected_unresolved();
        let unresolved_frontier_sha256 =
            digest_form(UNRESOLVED_DOMAIN, &unresolved_frontier).unwrap();
        let mut request = ProtocolFormationRequest {
            profile: PROTOCOL_REQUEST_PROFILE.to_owned(),
            root,
            stage_plan,
            capability_account,
            evidence,
            evidence_set_sha256,
            unresolved_frontier,
            unresolved_frontier_sha256,
            request_sha256: String::new(),
        };
        request.request_sha256 = protocol_request_digest(&request).unwrap();
        request
    }

    fn refresh(request: &mut ProtocolFormationRequest) {
        request.root.broker_root_sha256.clear();
        request.root.broker_root_sha256 = digest_form(ROOT_DOMAIN, &request.root).unwrap();
        request.stage_plan.stage_plan_sha256.clear();
        request.stage_plan.stage_plan_sha256 =
            digest_form(PLAN_DOMAIN, &request.stage_plan).unwrap();
        request.capability_account.capability_account_sha256.clear();
        request.capability_account.capability_account_sha256 =
            digest_form(CAPABILITY_DOMAIN, &request.capability_account).unwrap();
        request.evidence_set_sha256 = digest_form(EVIDENCE_DOMAIN, &request.evidence).unwrap();
        request.unresolved_frontier_sha256 =
            digest_form(UNRESOLVED_DOMAIN, &request.unresolved_frontier).unwrap();
        request.request_sha256 = protocol_request_digest(request).unwrap();
    }

    #[test]
    fn complete_protocol_compiles_and_replays() {
        let request = request();
        let result = compile_self_work_update_broker_protocol(&request).unwrap();
        assert!(!result.physical_contact);
        assert_eq!(result.authority, FormationAuthority::FormationOnly);
        assert_eq!(result.disposition, FormationDisposition::FormationValidated);
        validate_self_work_update_broker_protocol_result(&request, &result).unwrap();
        let request_bytes = to_protocol_request_machine_form(&request).unwrap();
        assert_eq!(
            from_protocol_request_machine_form(&request_bytes).unwrap(),
            request
        );
        let result_bytes = to_protocol_result_machine_form(&request, &result).unwrap();
        assert_eq!(
            from_protocol_result_machine_form(&request, &result_bytes).unwrap(),
            result
        );
    }

    #[test]
    fn exact_capability_set_has_twenty_two_unique_values() {
        let values = all_capabilities();
        assert_eq!(values.len(), 22);
        assert_eq!(values.iter().copied().collect::<HashSet<_>>().len(), 22);
    }

    #[test]
    fn any_capability_grant_refuses() {
        let mut request = request();
        request
            .capability_account
            .granted
            .push(CapabilityKind::ReadObservation);
        refresh(&mut request);
        assert_eq!(
            compile_self_work_update_broker_protocol(&request)
                .unwrap_err()
                .code,
            ProtocolFaultCode::Capability
        );
    }

    #[test]
    fn missing_capability_denial_refuses() {
        let mut request = request();
        request.capability_account.explicitly_not_granted.pop();
        refresh(&mut request);
        assert_eq!(
            compile_self_work_update_broker_protocol(&request)
                .unwrap_err()
                .code,
            ProtocolFaultCode::Capability
        );
    }

    #[test]
    fn stage_reorder_refuses() {
        let mut request = request();
        request.stage_plan.stages.swap(1, 2);
        refresh(&mut request);
        assert_eq!(
            compile_self_work_update_broker_protocol(&request)
                .unwrap_err()
                .code,
            ProtocolFaultCode::StagePlan
        );
    }

    #[test]
    fn physical_synthetic_evidence_refuses() {
        let mut request = request();
        request.evidence[0].physical_contact = true;
        refresh(&mut request);
        assert_eq!(
            compile_self_work_update_broker_protocol(&request)
                .unwrap_err()
                .code,
            ProtocolFaultCode::Evidence
        );
    }

    #[test]
    fn unresolved_gap_omission_refuses() {
        let mut request = request();
        request.unresolved_frontier.pop();
        refresh(&mut request);
        assert_eq!(
            compile_self_work_update_broker_protocol(&request)
                .unwrap_err()
                .code,
            ProtocolFaultCode::Unresolved
        );
    }

    #[test]
    fn traversal_and_unsorted_paths_refuse() {
        for paths in [
            vec!["../escape".to_owned()],
            vec!["z/path".to_owned(), "a/path".to_owned()],
        ] {
            let mut request = request();
            request.root.allowed_relative_paths = paths;
            refresh(&mut request);
            assert_eq!(
                compile_self_work_update_broker_protocol(&request)
                    .unwrap_err()
                    .code,
                ProtocolFaultCode::Path
            );
        }
    }

    #[test]
    fn generation_and_digest_substitution_refuse() {
        let mut generation = request();
        generation.root.protocol_canonical_uuid = generation.root.broker_uuid.clone();
        refresh(&mut generation);
        assert_eq!(
            compile_self_work_update_broker_protocol(&generation)
                .unwrap_err()
                .code,
            ProtocolFaultCode::Generation
        );

        let mut digest = request();
        digest.request_sha256 = sha('f');
        assert_eq!(
            compile_self_work_update_broker_protocol(&digest)
                .unwrap_err()
                .code,
            ProtocolFaultCode::Digest
        );
    }

    #[test]
    fn unknown_fields_and_authority_mutation_refuse() {
        let request = request();
        let mut value = serde_json::to_value(&request).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert_eq!(
            from_protocol_request_machine_form(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            ProtocolFaultCode::Serialization
        );

        let mut result = compile_self_work_update_broker_protocol(&request).unwrap();
        result.nonauthority.push_str(" widened");
        result.result_sha256 = protocol_result_digest(&result).unwrap();
        assert_eq!(
            validate_self_work_update_broker_protocol_result(&request, &result)
                .unwrap_err()
                .code,
            ProtocolFaultCode::Authority
        );
    }
}
