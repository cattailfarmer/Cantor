use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerRequest,
    Evox2ScratchBuildEffectProgram, Evox2ScratchBuildRemotePreflightProducerPlan,
};
use cantor_ecosystem::{
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_MANIFEST_PROFILE,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_NON_AUTHORITY,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID,
    EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID,
    Evox2RemotePreflightActivationEvidenceArtifact, Evox2RemotePreflightActivationEvidenceManifest,
    Evox2RemotePreflightActivationProposal, Evox2RemotePreflightOperatorDecision,
    Evox2RemotePreflightOperatorDecisionKind, activation_evidence_manifest_digest,
    canonical_evox2_remote_preflight_activation_request,
    compile_evox2_remote_preflight_activation_proposal, decision_correspondence_digest,
    evox2_remote_preflight_operator_decision_signing_bytes,
    seal_evox2_remote_preflight_operator_decision_digest,
    to_activation_evidence_manifest_machine_form,
    to_evox2_remote_preflight_activation_proposal_machine_form,
    to_evox2_remote_preflight_activation_proposal_verification_machine_form,
    to_evox2_remote_preflight_activation_request_machine_form,
    to_evox2_remote_preflight_decision_correspondence_machine_form,
    to_evox2_remote_preflight_operator_decision_machine_form,
    verify_evox2_remote_preflight_activation_evidence_directory,
    verify_evox2_remote_preflight_activation_proposal,
    verify_evox2_remote_preflight_operator_decision_correspondence,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

const CONTROLLER_REQUEST: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/controller_fixture/request.json"
);
const CONTROLLER_PLAN: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/controller_fixture/plan.json"
);
const PROGRAM: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/program.json"
);
const PRODUCER_PLAN: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/preflight_producer_fixture/producer_plan.json"
);
const ARTIFACTS: [&str; 11] = [
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
const EVIDENCE_CLI: &str =
    env!("CARGO_BIN_EXE_cantor-evox2-remote-preflight-activation-evidence-verify");
const RETAINED_EVIDENCE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence"
);
static NEXT_CASE: AtomicU64 = AtomicU64::new(1);

struct EvidenceRoot(PathBuf);

impl EvidenceRoot {
    fn new() -> Self {
        let parent = PathBuf::from(r"D:\CantorBuilds");
        let path = parent.join(format!(
            "evox2-activation-evidence-test-{}-{}",
            std::process::id(),
            NEXT_CASE.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path.starts_with(&parent));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for EvidenceRoot {
    fn drop(&mut self) {
        let parent = Path::new(r"D:\CantorBuilds");
        assert!(self.0.starts_with(parent));
        if self.0.exists() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn signed_decision(
    proposal: &Evox2RemotePreflightActivationProposal,
    decision: Evox2RemotePreflightOperatorDecisionKind,
    decision_uuid: &str,
) -> Evox2RemotePreflightOperatorDecision {
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let mut value = Evox2RemotePreflightOperatorDecision {
        profile: "cantor-evox2-remote-preflight-operator-decision/0.1".to_owned(),
        decision_uuid: decision_uuid.to_owned(),
        ceremony_uuid: proposal.ceremony_uuid.clone(),
        proposal_sha256: proposal.proposal_sha256.clone(),
        operator_principal: proposal.operator_principal.clone(),
        operator_role: proposal.operator_role.clone(),
        subject: proposal.subject.clone(),
        decision_nonce: proposal.decision_nonce.clone(),
        decision,
        issued_at_ms: proposal.decision_not_before_ms + 1,
        not_before_ms: proposal.decision_not_before_ms,
        expires_at_ms: proposal.decision_expires_at_ms,
        maximum_attempts: 1,
        maximum_permits: 1,
        maximum_processes: 1,
        retry_count: 0,
        verifying_key_hex: hex(&signing_key.verifying_key().to_bytes()),
        signature_hex: String::new(),
        fixture_only: true,
        decision_sha256: String::new(),
    };
    value.signature_hex = hex(&signing_key
        .sign(&evox2_remote_preflight_operator_decision_signing_bytes(&value).unwrap())
        .to_bytes());
    seal_evox2_remote_preflight_operator_decision_digest(value).unwrap()
}

fn write_evidence(root: &Path) {
    let controller_request: Evox2ScratchBuildControllerRequest =
        serde_json::from_str(CONTROLLER_REQUEST).unwrap();
    let controller_plan: Evox2ScratchBuildControllerPlan =
        serde_json::from_str(CONTROLLER_PLAN).unwrap();
    let program: Evox2ScratchBuildEffectProgram = serde_json::from_str(PROGRAM).unwrap();
    let producer_plan: Evox2ScratchBuildRemotePreflightProducerPlan =
        serde_json::from_str(PRODUCER_PLAN).unwrap();
    let request = canonical_evox2_remote_preflight_activation_request().unwrap();
    let proposal = compile_evox2_remote_preflight_activation_proposal(
        &request,
        &controller_request,
        &controller_plan,
        &program,
        &producer_plan,
    )
    .unwrap();
    let proposal_verification = verify_evox2_remote_preflight_activation_proposal(
        &request,
        &controller_request,
        &controller_plan,
        &program,
        &producer_plan,
        &proposal,
    )
    .unwrap();
    let authorize_decision = signed_decision(
        &proposal,
        Evox2RemotePreflightOperatorDecisionKind::Authorize,
        "530a596d-2cb2-4144-8296-dfe9e55c4650",
    );
    let reject_decision = signed_decision(
        &proposal,
        Evox2RemotePreflightOperatorDecisionKind::Reject,
        "40c524af-c96c-4b44-84d5-5234d0e1ddc1",
    );
    let observed_time = proposal.decision_not_before_ms + 2;
    let authorize = verify_evox2_remote_preflight_operator_decision_correspondence(
        &proposal,
        &authorize_decision,
        observed_time,
    )
    .unwrap();
    let reject = verify_evox2_remote_preflight_operator_decision_correspondence(
        &proposal,
        &reject_decision,
        observed_time,
    )
    .unwrap();

    let values = [
        serde_json::to_string(&controller_request).unwrap(),
        serde_json::to_string(&controller_plan).unwrap(),
        serde_json::to_string(&program).unwrap(),
        serde_json::to_string(&producer_plan).unwrap(),
        to_evox2_remote_preflight_activation_request_machine_form(&request).unwrap(),
        to_evox2_remote_preflight_activation_proposal_machine_form(&proposal).unwrap(),
        to_evox2_remote_preflight_activation_proposal_verification_machine_form(
            &proposal_verification,
        )
        .unwrap(),
        to_evox2_remote_preflight_operator_decision_machine_form(&authorize_decision).unwrap(),
        to_evox2_remote_preflight_decision_correspondence_machine_form(&authorize).unwrap(),
        to_evox2_remote_preflight_operator_decision_machine_form(&reject_decision).unwrap(),
        to_evox2_remote_preflight_decision_correspondence_machine_form(&reject).unwrap(),
    ];
    let mut artifacts = Vec::new();
    for (name, value) in ARTIFACTS.into_iter().zip(values) {
        fs::write(root.join(name), value.as_bytes()).unwrap();
        artifacts.push(Evox2RemotePreflightActivationEvidenceArtifact {
            path: name.to_owned(),
            bytes: value.len() as u64,
            sha256: sha256(value.as_bytes()),
        });
    }
    let mut manifest = Evox2RemotePreflightActivationEvidenceManifest {
        profile: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_MANIFEST_PROFILE.to_owned(),
        source_snapshot_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_CANONICAL_UUID.to_owned(),
        signature_uuid: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_SIGNATURE_UUID.to_owned(),
        formation_commit: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_COMMIT.to_owned(),
        formation_bookend: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_FORMATION_BOOKEND.to_owned(),
        authorize_observed_time_ms: observed_time,
        reject_observed_time_ms: observed_time,
        artifacts,
        fixture_only: true,
        permit_bridge_authorized: false,
        runner_invocation_authorized: false,
        non_authority_statement: EVOX2_REMOTE_PREFLIGHT_ACTIVATION_EVIDENCE_NON_AUTHORITY
            .to_owned(),
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = activation_evidence_manifest_digest(&manifest).unwrap();
    fs::write(
        root.join("evidence_manifest.json"),
        to_activation_evidence_manifest_machine_form(&manifest).unwrap(),
    )
    .unwrap();
}

fn rewrite_manifest(
    root: &Path,
    mutate: impl FnOnce(&mut Evox2RemotePreflightActivationEvidenceManifest),
) {
    let raw = fs::read_to_string(root.join("evidence_manifest.json")).unwrap();
    let mut manifest: Evox2RemotePreflightActivationEvidenceManifest =
        serde_json::from_str(&raw).unwrap();
    mutate(&mut manifest);
    manifest.manifest_sha256 = activation_evidence_manifest_digest(&manifest).unwrap();
    fs::write(
        root.join("evidence_manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();
}

fn update_artifact_identity(root: &Path, name: &str) {
    let bytes = fs::read(root.join(name)).unwrap();
    rewrite_manifest(root, |manifest| {
        let artifact = manifest
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.path == name)
            .unwrap();
        artifact.bytes = bytes.len() as u64;
        artifact.sha256 = sha256(&bytes);
    });
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

#[test]
fn evidence_replays_both_decision_branches_without_authority() {
    let root = EvidenceRoot::new();
    write_evidence(&root.0);
    let verified = verify_evox2_remote_preflight_activation_evidence_directory(&root.0).unwrap();
    assert_eq!(verified.artifact_count, 11);
    assert_eq!(verified.independent_replay_count, 2);
    assert!(verified.authorize_and_reject_distinct);
    assert!(verified.signature_correspondence);
    assert!(!verified.live_authorization_admitted);
    assert!(!verified.permit_mint_authorized);
    assert!(!verified.runner_invocation_authorized);
    assert_eq!(verified.effect_account, Default::default());
}

#[test]
fn evidence_cli_is_bounded_and_replays_the_same_summary() {
    let root = EvidenceRoot::new();
    write_evidence(&root.0);
    let direct = verify_evox2_remote_preflight_activation_evidence_directory(&root.0).unwrap();
    let success = Command::new(EVIDENCE_CLI).arg(&root.0).output().unwrap();
    assert!(success.status.success());
    let from_cli: cantor_ecosystem::Evox2RemotePreflightActivationEvidenceVerification =
        serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(from_cli, direct);

    let absent = Command::new(EVIDENCE_CLI).output().unwrap();
    assert_eq!(absent.status.code(), Some(2));
    let surplus = Command::new(EVIDENCE_CLI)
        .arg(&root.0)
        .arg("surplus")
        .output()
        .unwrap();
    assert_eq!(surplus.status.code(), Some(2));
}

#[test]
fn production_surfaces_do_not_gain_activation_effect_authority() {
    let ceremony = include_str!("../src/evox2_remote_preflight_one_shot_activation_ceremony.rs");
    let evidence =
        include_str!("../src/evox2_remote_preflight_one_shot_activation_ceremony_evidence.rs");
    let cli =
        include_str!("../src/bin/cantor-evox2-remote-preflight-activation-evidence-verify.rs");
    for forbidden in [
        "std::fs",
        "std::net",
        "std::process",
        "Command::",
        "SigningKey",
        "mint_private_execution_permit",
        "invoke_evox2_scratch_build_remote_preflight_runner",
    ] {
        assert!(!ceremony.contains(forbidden), "ceremony gained {forbidden}");
    }
    for forbidden in [
        "std::net",
        "Command::",
        "SigningKey",
        "mint_private_execution_permit",
        "invoke_evox2_scratch_build_remote_preflight_runner",
    ] {
        assert!(!evidence.contains(forbidden), "evidence gained {forbidden}");
        assert!(!cli.contains(forbidden), "CLI gained {forbidden}");
    }
}

#[test]
#[ignore = "writes the governed retained provider-free evidence exactly once"]
fn write_owned_retained_evidence() {
    assert_eq!(
        std::env::var("CANTOR_WRITE_EVOX2_ACTIVATION_EVIDENCE").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(RETAINED_EVIDENCE_ROOT);
    assert!(root.ends_with(
        "experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_provider_free_evidence"
    ));
    assert!(!root.exists(), "refusing to overwrite retained evidence");
    fs::create_dir_all(&root).unwrap();
    write_evidence(&root);
    let verification = verify_evox2_remote_preflight_activation_evidence_directory(&root).unwrap();
    fs::write(
        root.parent()
            .unwrap()
            .join("implementation_provider_free_verification.json"),
        cantor_ecosystem::to_activation_evidence_verification_machine_form(&verification).unwrap(),
    )
    .unwrap();
}

#[test]
fn raw_artifact_and_membership_tamper_refuse() {
    let root = EvidenceRoot::new();
    write_evidence(&root.0);
    fs::write(root.0.join("extra.json"), "{}").unwrap();
    assert!(verify_evox2_remote_preflight_activation_evidence_directory(&root.0).is_err());
    fs::remove_file(root.0.join("extra.json")).unwrap();
    let mut bytes = fs::read(root.0.join("proposal.json")).unwrap();
    bytes.push(b'\n');
    fs::write(root.0.join("proposal.json"), bytes).unwrap();
    assert!(verify_evox2_remote_preflight_activation_evidence_directory(&root.0).is_err());
}

#[test]
fn rehashed_authority_promotion_refuses() {
    let root = EvidenceRoot::new();
    write_evidence(&root.0);
    rewrite_manifest(&root.0, |manifest| manifest.permit_bridge_authorized = true);
    assert!(verify_evox2_remote_preflight_activation_evidence_directory(&root.0).is_err());
}

#[test]
fn rehashed_correspondence_substitution_refuses() {
    let root = EvidenceRoot::new();
    write_evidence(&root.0);
    let path = root.0.join("authorize_correspondence.json");
    let mut correspondence: cantor_ecosystem::Evox2RemotePreflightDecisionCorrespondence =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    correspondence.live_authorization_admitted = true;
    correspondence.correspondence_sha256 = decision_correspondence_digest(&correspondence).unwrap();
    fs::write(&path, serde_json::to_string(&correspondence).unwrap()).unwrap();
    update_artifact_identity(&root.0, "authorize_correspondence.json");
    assert!(verify_evox2_remote_preflight_activation_evidence_directory(&root.0).is_err());
}
