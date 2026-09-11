//! Independent read-only replay of provider-free activation-ceremony evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::Write as _,
    fs,
    path::Path,
};

use cantor_core::{
    Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerRequest,
    Evox2ScratchBuildEffectProgram, Evox2ScratchBuildRemotePreflightProducerPlan,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY, EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_MAX_MACHINE_BYTES,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID,
    Evox2RemotePreflightActivationEffectAccount, Evox2RemotePreflightActivationProposal,
    Evox2RemotePreflightActivationProposalVerification, Evox2RemotePreflightActivationRequest,
    Evox2RemotePreflightDecisionCorrespondence, Evox2RemotePreflightOperatorDecision,
    from_evox2_remote_preflight_activation_proposal_machine_form,
    from_evox2_remote_preflight_activation_proposal_verification_machine_form,
    from_evox2_remote_preflight_activation_request_machine_form,
    from_evox2_remote_preflight_operator_decision_machine_form,
    to_evox2_remote_preflight_activation_proposal_verification_machine_form,
    to_evox2_remote_preflight_decision_correspondence_machine_form,
    verify_evox2_remote_preflight_activation_proposal,
    verify_evox2_remote_preflight_operator_decision_correspondence,
};

pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_MANIFEST_PROFILE: &str =
    "cantor-evox2-remote-preflight-activation-evidence-manifest/0.1";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_VERIFICATION_PROFILE: &str =
    "cantor-evox2-remote-preflight-activation-evidence-verification/0.1";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_STATUS: &str =
    "provider_free_proposal_and_decision_correspondence_verified_live_authority_absent";
pub const EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_NON_AUTHORITY: &str = "Provider-free evidence proves deterministic proposal and supplied signature correspondence only. It does not prove operator identity authority, key custody, trusted current time, live authorization, permit minting, runner invocation, provider state, remote state, or any effect.";

const MANIFEST_DOMAIN: &[u8] = b"cantor-evox2-remote-preflight-activation-evidence-manifest-v1\0";
const VERIFICATION_DOMAIN: &[u8] =
    b"cantor-evox2-remote-preflight-activation-evidence-verification-v1\0";
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_FIELDS: usize = 512;
const MAX_AGGREGATE_BYTES: u64 = 4 * 1024 * 1024;
const EXPECTED_ARTIFACTS: [&str; 11] = [
    "controller_request.json",
    "controller_plan.json",
    "program.json",
    "producer_plan.json",
    "activation_request.json",
    "proposal.json",
    "proposal_verification.json",
    "authorize_decision.json",
    "authorize_correspondence.json",
    "reject_decision.json",
    "reject_correspondence.json",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationEvidenceArtifact {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationEvidenceManifest {
    pub profile: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub authorize_observed_time_ms: u64,
    pub reject_observed_time_ms: u64,
    pub artifacts: Vec<Evox2RemotePreflightActivationEvidenceArtifact>,
    pub fixture_only: bool,
    pub permit_bridge_authorized: bool,
    pub runner_invocation_authorized: bool,
    pub non_authority_statement: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evox2RemotePreflightActivationEvidenceVerification {
    pub profile: String,
    pub status: String,
    pub authority: String,
    pub source_snapshot_uuid: String,
    pub canonical_uuid: String,
    pub signature_uuid: String,
    pub formation_commit: String,
    pub formation_bookend: String,
    pub request_sha256: String,
    pub proposal_sha256: String,
    pub proposal_verification_sha256: String,
    pub authorize_decision_sha256: String,
    pub authorize_correspondence_sha256: String,
    pub reject_decision_sha256: String,
    pub reject_correspondence_sha256: String,
    pub artifact_count: u8,
    pub independent_replay_count: u8,
    pub byte_identical: bool,
    pub role_count: u8,
    pub stage_count: u8,
    pub authorize_and_reject_distinct: bool,
    pub signature_correspondence: bool,
    pub live_authorization_admitted: bool,
    pub permit_mint_authorized: bool,
    pub runner_invocation_authorized: bool,
    pub fixture_only: bool,
    pub effect_account: Evox2RemotePreflightActivationEffectAccount,
    pub evidence_verification_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evox2RemotePreflightActivationEvidenceFault {
    pub detail: String,
}

impl fmt::Display for Evox2RemotePreflightActivationEvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for Evox2RemotePreflightActivationEvidenceFault {}

pub fn verify_evox2_remote_preflight_activation_evidence_directory(
    root: &Path,
) -> Result<
    Evox2RemotePreflightActivationEvidenceVerification,
    Evox2RemotePreflightActivationEvidenceFault,
> {
    let metadata = fs::symlink_metadata(root).map_err(evidence_fault)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(evidence_fault(
            "evidence root must be one nonlink directory",
        ));
    }
    let actual: BTreeSet<String> = fs::read_dir(root)
        .map_err(evidence_fault)?
        .map(|entry| {
            entry.map_err(evidence_fault).and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| evidence_fault("evidence name is not UTF-8"))
            })
        })
        .collect::<Result<_, _>>()?;
    let expected: BTreeSet<String> = EXPECTED_ARTIFACTS
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once("evidence_manifest.json".to_owned()))
        .collect();
    if actual != expected {
        return Err(evidence_fault("evidence directory membership differs"));
    }

    let manifest_text = read_text(root, "evidence_manifest.json")?;
    let manifest: Evox2RemotePreflightActivationEvidenceManifest = parse_canonical(&manifest_text)?;
    validate_manifest(&manifest)?;
    let texts = read_artifacts(root, &manifest)?;

    let controller_request: Evox2ScratchBuildControllerRequest =
        parse_named(&texts, "controller_request.json")?;
    let controller_plan: Evox2ScratchBuildControllerPlan =
        parse_named(&texts, "controller_plan.json")?;
    let program: Evox2ScratchBuildEffectProgram = parse_named(&texts, "program.json")?;
    let producer_plan: Evox2ScratchBuildRemotePreflightProducerPlan =
        parse_named(&texts, "producer_plan.json")?;
    let request = from_evox2_remote_preflight_activation_request_machine_form(text(
        &texts,
        "activation_request.json",
    )?)
    .map_err(evidence_fault)?;
    let proposal = from_evox2_remote_preflight_activation_proposal_machine_form(text(
        &texts,
        "proposal.json",
    )?)
    .map_err(evidence_fault)?;
    let retained_proposal_verification =
        from_evox2_remote_preflight_activation_proposal_verification_machine_form(text(
            &texts,
            "proposal_verification.json",
        )?)
        .map_err(evidence_fault)?;
    let replayed_proposal_verification = verify_evox2_remote_preflight_activation_proposal(
        &request,
        &controller_request,
        &controller_plan,
        &program,
        &producer_plan,
        &proposal,
    )
    .map_err(evidence_fault)?;
    if retained_proposal_verification != replayed_proposal_verification
        || to_evox2_remote_preflight_activation_proposal_verification_machine_form(
            &replayed_proposal_verification,
        )
        .map_err(evidence_fault)?
            != text(&texts, "proposal_verification.json")?
    {
        return Err(evidence_fault("proposal verification replay differs"));
    }

    let authorize_decision = parse_decision(&texts, "authorize_decision.json")?;
    let retained_authorize: Evox2RemotePreflightDecisionCorrespondence =
        parse_named(&texts, "authorize_correspondence.json")?;
    let authorize = verify_evox2_remote_preflight_operator_decision_correspondence(
        &proposal,
        &authorize_decision,
        manifest.authorize_observed_time_ms,
    )
    .map_err(evidence_fault)?;
    require_correspondence(
        &authorize,
        &retained_authorize,
        text(&texts, "authorize_correspondence.json")?,
    )?;

    let reject_decision = parse_decision(&texts, "reject_decision.json")?;
    let retained_reject: Evox2RemotePreflightDecisionCorrespondence =
        parse_named(&texts, "reject_correspondence.json")?;
    let reject = verify_evox2_remote_preflight_operator_decision_correspondence(
        &proposal,
        &reject_decision,
        manifest.reject_observed_time_ms,
    )
    .map_err(evidence_fault)?;
    require_correspondence(
        &reject,
        &retained_reject,
        text(&texts, "reject_correspondence.json")?,
    )?;

    compile_evidence_verification(
        &request,
        &proposal,
        &replayed_proposal_verification,
        &authorize_decision,
        &authorize,
        &reject_decision,
        &reject,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compile_evidence_verification(
    request: &Evox2RemotePreflightActivationRequest,
    proposal: &Evox2RemotePreflightActivationProposal,
    proposal_verification: &Evox2RemotePreflightActivationProposalVerification,
    authorize_decision: &Evox2RemotePreflightOperatorDecision,
    authorize: &Evox2RemotePreflightDecisionCorrespondence,
    reject_decision: &Evox2RemotePreflightOperatorDecision,
    reject: &Evox2RemotePreflightDecisionCorrespondence,
) -> Result<
    Evox2RemotePreflightActivationEvidenceVerification,
    Evox2RemotePreflightActivationEvidenceFault,
> {
    if authorize.decision == reject.decision
        || authorize.live_authorization_admitted
        || reject.live_authorization_admitted
    {
        return Err(evidence_fault(
            "decision branches collapsed or promoted authority",
        ));
    }
    let mut verification = Evox2RemotePreflightActivationEvidenceVerification {
        profile: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_VERIFICATION_PROFILE.to_owned(),
        status: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_STATUS.to_owned(),
        authority: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY.to_owned(),
        source_snapshot_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID.to_owned(),
        signature_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID.to_owned(),
        formation_commit: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT.to_owned(),
        formation_bookend: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND.to_owned(),
        request_sha256: request.request_sha256.clone(),
        proposal_sha256: proposal.proposal_sha256.clone(),
        proposal_verification_sha256: proposal_verification.proposal_verification_sha256.clone(),
        authorize_decision_sha256: authorize_decision.decision_sha256.clone(),
        authorize_correspondence_sha256: authorize.correspondence_sha256.clone(),
        reject_decision_sha256: reject_decision.decision_sha256.clone(),
        reject_correspondence_sha256: reject.correspondence_sha256.clone(),
        artifact_count: EXPECTED_ARTIFACTS.len() as u8,
        independent_replay_count: 2,
        byte_identical: true,
        role_count: 8,
        stage_count: 8,
        authorize_and_reject_distinct: true,
        signature_correspondence: true,
        live_authorization_admitted: false,
        permit_mint_authorized: false,
        runner_invocation_authorized: false,
        fixture_only: true,
        effect_account: Evox2RemotePreflightActivationEffectAccount::default(),
        evidence_verification_sha256: String::new(),
    };
    verification.evidence_verification_sha256 = evidence_verification_digest(&verification)?;
    validate_evidence_verification(&verification)?;
    Ok(verification)
}

pub fn activation_evidence_manifest_digest(
    manifest: &Evox2RemotePreflightActivationEvidenceManifest,
) -> Result<String, Evox2RemotePreflightActivationEvidenceFault> {
    let mut normalized = manifest.clone();
    normalized.manifest_sha256.clear();
    domain_digest(MANIFEST_DOMAIN, &normalized)
}

pub fn to_activation_evidence_manifest_machine_form(
    manifest: &Evox2RemotePreflightActivationEvidenceManifest,
) -> Result<String, Evox2RemotePreflightActivationEvidenceFault> {
    validate_manifest(manifest)?;
    serde_json::to_string(manifest).map_err(evidence_fault)
}

pub fn to_activation_evidence_verification_machine_form(
    verification: &Evox2RemotePreflightActivationEvidenceVerification,
) -> Result<String, Evox2RemotePreflightActivationEvidenceFault> {
    validate_evidence_verification(verification)?;
    serde_json::to_string(verification).map_err(evidence_fault)
}

fn read_artifacts(
    root: &Path,
    manifest: &Evox2RemotePreflightActivationEvidenceManifest,
) -> Result<BTreeMap<String, String>, Evox2RemotePreflightActivationEvidenceFault> {
    let mut texts = BTreeMap::new();
    let mut aggregate = 0_u64;
    for artifact in &manifest.artifacts {
        let bytes = read_bytes(root, &artifact.path)?;
        aggregate = aggregate
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| evidence_fault("aggregate evidence bytes overflowed"))?;
        if aggregate > MAX_AGGREGATE_BYTES
            || bytes.len() as u64 != artifact.bytes
            || sha256_hex(&bytes) != artifact.sha256
        {
            return Err(evidence_fault(format!(
                "artifact identity differs: {}",
                artifact.path
            )));
        }
        texts.insert(
            artifact.path.clone(),
            String::from_utf8(bytes).map_err(evidence_fault)?,
        );
    }
    Ok(texts)
}

fn validate_manifest(
    manifest: &Evox2RemotePreflightActivationEvidenceManifest,
) -> Result<(), Evox2RemotePreflightActivationEvidenceFault> {
    let paths: Vec<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();
    if manifest.profile != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_MANIFEST_PROFILE
        || manifest.source_snapshot_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID
        || manifest.canonical_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID
        || manifest.signature_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID
        || manifest.formation_commit != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT
        || manifest.formation_bookend != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND
        || paths != EXPECTED_ARTIFACTS
        || !manifest.fixture_only
        || manifest.permit_bridge_authorized
        || manifest.runner_invocation_authorized
        || manifest.non_authority_statement
            != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_NON_AUTHORITY
        || manifest.authorize_observed_time_ms == 0
        || manifest.reject_observed_time_ms == 0
        || manifest.artifacts.iter().any(|artifact| {
            artifact.bytes == 0
                || artifact.bytes > EVOX2_REMOTE_PREFLIGHT_ACTIVATION_MAX_MACHINE_BYTES as u64
                || !is_lower_hex(&artifact.sha256, 64)
                || artifact.path.contains('/')
                || artifact.path.contains('\\')
                || artifact.path == "evidence_manifest.json"
        })
        || manifest.manifest_sha256 != activation_evidence_manifest_digest(manifest)?
    {
        return Err(evidence_fault("activation evidence manifest differs"));
    }
    Ok(())
}

fn validate_evidence_verification(
    verification: &Evox2RemotePreflightActivationEvidenceVerification,
) -> Result<(), Evox2RemotePreflightActivationEvidenceFault> {
    if verification.profile != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_VERIFICATION_PROFILE
        || verification.status != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_STATUS
        || verification.authority != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_AUTHORITY
        || verification.source_snapshot_uuid
            != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID
        || verification.canonical_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID
        || verification.signature_uuid != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID
        || verification.formation_commit != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT
        || verification.formation_bookend != EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND
        || verification.artifact_count != EXPECTED_ARTIFACTS.len() as u8
        || verification.independent_replay_count != 2
        || !verification.byte_identical
        || verification.role_count != 8
        || verification.stage_count != 8
        || !verification.authorize_and_reject_distinct
        || !verification.signature_correspondence
        || verification.live_authorization_admitted
        || verification.permit_mint_authorized
        || verification.runner_invocation_authorized
        || !verification.fixture_only
        || verification.effect_account != Evox2RemotePreflightActivationEffectAccount::default()
        || verification.evidence_verification_sha256 != evidence_verification_digest(verification)?
    {
        return Err(evidence_fault(
            "activation evidence verification differs or promotes authority",
        ));
    }
    Ok(())
}

fn require_correspondence(
    replayed: &Evox2RemotePreflightDecisionCorrespondence,
    retained: &Evox2RemotePreflightDecisionCorrespondence,
    retained_text: &str,
) -> Result<(), Evox2RemotePreflightActivationEvidenceFault> {
    if replayed != retained
        || to_evox2_remote_preflight_decision_correspondence_machine_form(replayed)
            .map_err(evidence_fault)?
            != retained_text
    {
        return Err(evidence_fault("decision correspondence replay differs"));
    }
    Ok(())
}

fn parse_decision(
    texts: &BTreeMap<String, String>,
    name: &str,
) -> Result<Evox2RemotePreflightOperatorDecision, Evox2RemotePreflightActivationEvidenceFault> {
    from_evox2_remote_preflight_operator_decision_machine_form(text(texts, name)?)
        .map_err(evidence_fault)
}

fn parse_named<T: DeserializeOwned + Serialize>(
    texts: &BTreeMap<String, String>,
    name: &str,
) -> Result<T, Evox2RemotePreflightActivationEvidenceFault> {
    parse_canonical(text(texts, name)?)
}

fn text<'a>(
    texts: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, Evox2RemotePreflightActivationEvidenceFault> {
    texts
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| evidence_fault(format!("evidence artifact absent: {name}")))
}

fn read_text(
    root: &Path,
    name: &str,
) -> Result<String, Evox2RemotePreflightActivationEvidenceFault> {
    String::from_utf8(read_bytes(root, name)?).map_err(evidence_fault)
}

fn read_bytes(
    root: &Path,
    name: &str,
) -> Result<Vec<u8>, Evox2RemotePreflightActivationEvidenceFault> {
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(evidence_fault)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > EVOX2_REMOTE_PREFLIGHT_ACTIVATION_MAX_MACHINE_BYTES as u64
    {
        return Err(evidence_fault(format!(
            "evidence artifact is not one bounded regular nonlink file: {name}"
        )));
    }
    fs::read(path).map_err(evidence_fault)
}

fn parse_canonical<T: DeserializeOwned + Serialize>(
    machine_form: &str,
) -> Result<T, Evox2RemotePreflightActivationEvidenceFault> {
    if machine_form.is_empty()
        || machine_form.len() > EVOX2_REMOTE_PREFLIGHT_ACTIVATION_MAX_MACHINE_BYTES
    {
        return Err(evidence_fault("machine-form byte bound differs"));
    }
    let value: Value = serde_json::from_str(machine_form).map_err(evidence_fault)?;
    let mut fields = 0_usize;
    measure_value(&value, 1, &mut fields)?;
    let parsed: T = serde_json::from_str(machine_form).map_err(evidence_fault)?;
    if serde_json::to_string(&parsed).map_err(evidence_fault)? != machine_form {
        return Err(evidence_fault(
            "machine form is not canonical duplicate-free JSON",
        ));
    }
    Ok(parsed)
}

fn measure_value(
    value: &Value,
    depth: usize,
    fields: &mut usize,
) -> Result<(), Evox2RemotePreflightActivationEvidenceFault> {
    if depth > MAX_JSON_DEPTH {
        return Err(evidence_fault("JSON depth exceeds bound"));
    }
    match value {
        Value::Object(map) => {
            *fields = fields
                .checked_add(map.len())
                .ok_or_else(|| evidence_fault("JSON field count overflowed"))?;
            if *fields > MAX_JSON_FIELDS {
                return Err(evidence_fault("JSON field count exceeds bound"));
            }
            for child in map.values() {
                measure_value(child, depth + 1, fields)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                measure_value(child, depth + 1, fields)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn evidence_verification_digest(
    verification: &Evox2RemotePreflightActivationEvidenceVerification,
) -> Result<String, Evox2RemotePreflightActivationEvidenceFault> {
    let mut normalized = verification.clone();
    normalized.evidence_verification_sha256.clear();
    domain_digest(VERIFICATION_DOMAIN, &normalized)
}

fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, Evox2RemotePreflightActivationEvidenceFault> {
    let payload = serde_json::to_vec(value).map_err(evidence_fault)?;
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&payload);
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn evidence_fault(error: impl fmt::Display) -> Evox2RemotePreflightActivationEvidenceFault {
    Evox2RemotePreflightActivationEvidenceFault {
        detail: error.to_string(),
    }
}
