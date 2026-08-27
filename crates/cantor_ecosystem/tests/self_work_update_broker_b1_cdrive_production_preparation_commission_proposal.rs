use std::{
    fs,
    path::{Path, PathBuf},
};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::{
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_AUTHORITY,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_MANIFEST_PROFILE,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_FORMATION_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_PROFILE,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_STATUS,
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID,
    B1CDriveProductionPreparationCommissionProposal,
    B1CDriveProductionPreparationCommissionProposalEvidenceArtifact,
    B1CDriveProductionPreparationCommissionProposalEvidenceManifest,
    B1CDriveProductionPreparationCommissionProposalFaultCode,
    B1CDriveProductionPreparationCommissionProposalRequest,
    B1CDriveProductionPreparationContactOutcome,
    b1_cdrive_production_preparation_commission_proposal_digest,
    b1_cdrive_production_preparation_commission_proposal_evidence_manifest_digest,
    b1_cdrive_production_preparation_commission_proposal_request_digest,
    canonical_b1_cdrive_production_preparation_commission_proposal_request,
    compile_b1_cdrive_production_preparation_commission_proposal,
    compile_b1_cdrive_production_preparation_commission_proposal_evidence_verification,
    from_b1_cdrive_production_preparation_commission_proposal_machine_form,
    from_b1_cdrive_production_preparation_commission_proposal_request_machine_form,
    to_b1_cdrive_production_preparation_commission_proposal_evidence_manifest_machine_form,
    to_b1_cdrive_production_preparation_commission_proposal_evidence_verification_machine_form,
    to_b1_cdrive_production_preparation_commission_proposal_machine_form,
    to_b1_cdrive_production_preparation_commission_proposal_request_machine_form,
    validate_b1_cdrive_production_preparation_commission_proposal,
    verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory,
};

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn fixture_request() -> B1CDriveProductionPreparationCommissionProposalRequest {
    canonical_b1_cdrive_production_preparation_commission_proposal_request().unwrap()
}

fn redigest_request(request: &mut B1CDriveProductionPreparationCommissionProposalRequest) {
    request.request_sha256 = empty_digest();
    request.request_sha256 =
        b1_cdrive_production_preparation_commission_proposal_request_digest(request).unwrap();
}

fn redigest_proposal(proposal: &mut B1CDriveProductionPreparationCommissionProposal) {
    proposal.proposal_sha256 = empty_digest();
    proposal.proposal_sha256 =
        b1_cdrive_production_preparation_commission_proposal_digest(proposal).unwrap();
}

#[test]
fn valid_proposal_is_deterministic_closed_and_zero_effect() {
    let request = fixture_request();
    let first = compile_b1_cdrive_production_preparation_commission_proposal(&request).unwrap();
    let second = compile_b1_cdrive_production_preparation_commission_proposal(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.profile,
        B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_PROFILE
    );
    assert_eq!(
        first.status,
        B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_STATUS
    );
    assert_eq!(
        first.authority,
        B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_AUTHORITY
    );
    assert_eq!(
        first.proposal_uuid,
        B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID
    );
    assert_eq!(request.planner_artifacts.len(), 4);
    assert_eq!(first.roles.len(), 5);
    assert_eq!(first.operations.len(), 12);
    assert_eq!(first.responsibilities.len(), 9);
    assert_eq!(first.authorization_gaps.len(), 5);
    assert!(
        first
            .responsibilities
            .iter()
            .all(|entry| entry.ceiling == 1 && entry.actual_count == 0)
    );
    assert!(!first.external_authorization_present);
    assert!(!first.physical_preparation_authorized);
    assert_eq!(first.effect_account, Default::default());
}

#[test]
fn request_and_proposal_machine_forms_are_exact_duplicate_free_and_bounded() {
    let request = fixture_request();
    let request_text =
        to_b1_cdrive_production_preparation_commission_proposal_request_machine_form(&request)
            .unwrap();
    assert_eq!(
        from_b1_cdrive_production_preparation_commission_proposal_request_machine_form(
            &request_text,
        )
        .unwrap(),
        request
    );
    let proposal = compile_b1_cdrive_production_preparation_commission_proposal(&request).unwrap();
    let proposal_text =
        to_b1_cdrive_production_preparation_commission_proposal_machine_form(&request, &proposal)
            .unwrap();
    assert_eq!(
        from_b1_cdrive_production_preparation_commission_proposal_machine_form(
            &request,
            &proposal_text,
        )
        .unwrap(),
        proposal
    );
    assert!(
        from_b1_cdrive_production_preparation_commission_proposal_request_machine_form(
            &(request_text.clone() + "\n"),
        )
        .is_err()
    );
    let duplicate = request_text.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert!(
        from_b1_cdrive_production_preparation_commission_proposal_request_machine_form(&duplicate)
            .is_err()
    );
    let unknown = request_text.replacen("{", "{\"unknown\":0,", 1);
    assert!(
        from_b1_cdrive_production_preparation_commission_proposal_request_machine_form(&unknown)
            .is_err()
    );
}

#[test]
fn request_lineage_raw_artifact_coordinate_uuid_and_ceiling_drift_refuse() {
    let base = fixture_request();
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.expected_current_commit = "0".repeat(40);
    variants.push(changed);
    let mut changed = base.clone();
    changed.planner_artifacts[0]
        .sha256
        .value
        .replace_range(0..1, "0");
    variants.push(changed);
    let mut changed = base.clone();
    changed.planner_artifacts.swap(0, 1);
    variants.push(changed);
    let mut changed = base.clone();
    changed.roles.swap(0, 1);
    variants.push(changed);
    let mut changed = base.clone();
    changed.proposed_ref.push_str("-drift");
    variants.push(changed);
    let mut changed = base.clone();
    changed.proposal_uuid =
        B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID.to_owned();
    variants.push(changed);
    let mut changed = base.clone();
    changed.recovery_owner = "unowned".to_owned();
    variants.push(changed);
    let mut changed = base.clone();
    changed.attempt_ceiling = 2;
    variants.push(changed);
    let mut changed = base.clone();
    changed.retry_ceiling = 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.automatic_cleanup_ceiling = 1;
    variants.push(changed);
    for mut variant in variants {
        redigest_request(&mut variant);
        assert!(compile_b1_cdrive_production_preparation_commission_proposal(&variant).is_err());
    }
}

#[test]
fn proposal_order_responsibility_gap_quarantine_authorization_and_effect_laundering_refuse() {
    let request = fixture_request();
    let proposal = compile_b1_cdrive_production_preparation_commission_proposal(&request).unwrap();
    let mut variants = Vec::new();
    let mut changed = proposal.clone();
    changed.operations.swap(0, 1);
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.responsibilities.swap(0, 1);
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.responsibilities[0].ceiling = 2;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.responsibilities[0].actual_count = 1;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.authorization_gaps.remove(0);
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.quarantine_policy.maximum_attempts = 2;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.quarantine_policy.retry_count = 1;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.quarantine_policy.automatic_cleanup_count = 1;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.quarantine_policy.post_contact_retained_state = false;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.quarantine_policy.success_receipt_possible = true;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.external_authorization_present = true;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.physical_preparation_authorized = true;
    variants.push(changed);
    let mut changed = proposal.clone();
    changed.effect_account.process_count = 1;
    variants.push(changed);
    for mut variant in variants {
        redigest_proposal(&mut variant);
        assert!(
            validate_b1_cdrive_production_preparation_commission_proposal(&request, &variant)
                .is_err()
        );
    }
}

#[test]
fn precontact_not_run_and_postcontact_quarantine_are_explicit_without_success() {
    let request = fixture_request();
    let proposal = compile_b1_cdrive_production_preparation_commission_proposal(&request).unwrap();
    let policy = proposal.quarantine_policy;
    assert_eq!(
        policy.pre_contact_drift_outcome,
        B1CDriveProductionPreparationContactOutcome::NotRun
    );
    assert!(!policy.pre_contact_retained_state);
    assert_eq!(policy.pre_contact_created_object_count, 0);
    assert_eq!(
        policy.post_contact_ambiguity_outcome,
        B1CDriveProductionPreparationContactOutcome::Quarantined
    );
    assert!(policy.post_contact_retained_state);
    assert_eq!(policy.recovery_owner, r"THEBRAIN\enjer");
    assert!(!policy.success_receipt_possible);
}

#[test]
fn retained_evidence_replays_independently_without_authorization_or_effects() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../experiments/self_work_update_broker_b1_cdrive_production_preparation_commission_proposal_p0/implementation_provider_free_evidence",
    );
    let left =
        verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory(&root)
            .unwrap();
    let right =
        verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory(&root)
            .unwrap();
    assert_eq!(left, right);
    assert_eq!(left.independent_replay_count, 2);
    assert!(left.byte_identical_replays);
    assert_eq!(left.responsibility_count, 9);
    assert_eq!(left.unresolved_gap_count, 5);
    assert!(!left.external_authorization_present);
    assert!(!left.physical_preparation_authorized);
    assert_eq!(left.effect_account, Default::default());
}

#[test]
fn evidence_refuses_extra_entry_and_raw_argument_byte_tamper() {
    let root = temporary_root("tamper");
    write_evidence(&root);
    fs::write(root.join("extra.json"), b"{}").unwrap();
    assert!(
        verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory(&root)
            .is_err()
    );
    fs::remove_file(root.join("extra.json")).unwrap();
    let mut request = fs::read(root.join("request.json")).unwrap();
    request.push(b'\n');
    fs::write(root.join("request.json"), request).unwrap();
    assert!(
        verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory(&root)
            .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn evidence_refuses_manifest_coordinate_and_retained_verification_tamper() {
    let root = temporary_root("manifest");
    write_evidence(&root);
    let manifest_path = root.join("evidence_manifest.json");
    let manifest_text = fs::read_to_string(&manifest_path).unwrap();
    let changed = manifest_text.replacen("request.json", "request-drift.json", 1);
    fs::write(&manifest_path, changed).unwrap();
    assert!(
        verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory(&root)
            .is_err()
    );
    fs::remove_dir_all(&root).unwrap();

    let root = temporary_root("verification");
    write_evidence(&root);
    let verification_path = root.join("verification.json");
    let mut verification = fs::read(&verification_path).unwrap();
    verification[0] = b'[';
    fs::write(&verification_path, verification).unwrap();
    assert!(
        verify_b1_cdrive_production_preparation_commission_proposal_evidence_directory(&root)
            .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn proposal_and_verifier_effect_surfaces_remain_statically_locked() {
    let proposal_source = include_str!(
        "../src/self_work_update_broker_b1_cdrive_production_preparation_commission_proposal.rs"
    );
    let evidence_source = include_str!(
        "../src/self_work_update_broker_b1_cdrive_production_preparation_commission_proposal_evidence.rs"
    );
    for forbidden in [
        "std::process",
        "Command::",
        "std::env",
        "SystemTime",
        "TcpStream",
        "unsafe",
        "fs::write",
        "create_dir",
        "remove_dir",
    ] {
        assert!(
            !proposal_source.contains(forbidden),
            "proposal effect surface: {forbidden}"
        );
        assert!(
            !evidence_source.contains(forbidden),
            "verifier effect surface: {forbidden}"
        );
    }
    assert!(include_str!("../../../narrative/registries/Cantor_Self_Work_Update_Broker_B1_CDrive_Production_Preparation_Commission_Proposal_P0_Satisfaction_Signature.sop").contains(B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID));
    assert!(include_str!("../../../source_documents/2026-08-27_cantor_self_work_update_broker_b1_cdrive_production_preparation_commission_proposal_p0/Cantor_Self_Work_Update_Broker_B1_CDrive_Production_Preparation_Commission_Proposal_P0_Source.sop").contains(B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID));
}

#[test]
fn fault_codes_distinguish_artifact_from_proposal_order() {
    let mut request = fixture_request();
    request.planner_artifacts[0].bytes += 1;
    redigest_request(&mut request);
    assert_eq!(
        compile_b1_cdrive_production_preparation_commission_proposal(&request)
            .unwrap_err()
            .code,
        B1CDriveProductionPreparationCommissionProposalFaultCode::Artifact
    );
    let request = fixture_request();
    let mut proposal =
        compile_b1_cdrive_production_preparation_commission_proposal(&request).unwrap();
    proposal.operations.swap(0, 1);
    redigest_proposal(&mut proposal);
    assert_eq!(
        validate_b1_cdrive_production_preparation_commission_proposal(&request, &proposal)
            .unwrap_err()
            .code,
        B1CDriveProductionPreparationCommissionProposalFaultCode::Order
    );
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_provider_free_production_preparation_commission_proposal_evidence() {
    let root = std::env::var_os("CANTOR_B1PCP_EVIDENCE_ROOT")
        .map(PathBuf::from)
        .expect("CANTOR_B1PCP_EVIDENCE_ROOT");
    assert!(!root.exists(), "owned evidence root must be absent");
    write_evidence(&root);
}

fn write_evidence(root: &Path) {
    fs::create_dir(root).unwrap();
    let request = fixture_request();
    let proposal = compile_b1_cdrive_production_preparation_commission_proposal(&request).unwrap();
    let verification =
        compile_b1_cdrive_production_preparation_commission_proposal_evidence_verification(
            &request, &proposal,
        )
        .unwrap();
    let request_text =
        to_b1_cdrive_production_preparation_commission_proposal_request_machine_form(&request)
            .unwrap();
    let proposal_text =
        to_b1_cdrive_production_preparation_commission_proposal_machine_form(&request, &proposal)
            .unwrap();
    let verification_text =
        to_b1_cdrive_production_preparation_commission_proposal_evidence_verification_machine_form(
            &verification,
        )
        .unwrap();
    let artifacts = [
        ("request.json", request_text.as_bytes()),
        ("proposal.json", proposal_text.as_bytes()),
        ("verification.json", verification_text.as_bytes()),
    ]
    .into_iter()
    .map(
        |(path, bytes)| B1CDriveProductionPreparationCommissionProposalEvidenceArtifact {
            path: path.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(bytes),
        },
    )
    .collect();
    let mut manifest = B1CDriveProductionPreparationCommissionProposalEvidenceManifest {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_EVIDENCE_MANIFEST_PROFILE
            .to_owned(),
        source_snapshot_uuid:
            B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: cantor_ecosystem::B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_SIGNATURE_UUID
            .to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_FORMATION_COMMIT
            .to_owned(),
        proposal_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_UUID.to_owned(),
        artifacts,
        external_authorization_present: false,
        physical_execution_authorized: false,
        non_authority_statement: "Provider-free proposal evidence only; no external authorization, live observation, private permit, physical preparation, scratch namespace, worktree, ref, evidence root, lease, ledger, Phase3A, prepared receipt, process, provider, model, MCP, network, writer, Git or filesystem runtime mutation, persistence, activation, D-drive runtime contact, cleanup, or foreign effect.".to_owned(),
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 =
        b1_cdrive_production_preparation_commission_proposal_evidence_manifest_digest(&manifest)
            .unwrap();
    fs::write(root.join("request.json"), request_text).unwrap();
    fs::write(root.join("proposal.json"), proposal_text).unwrap();
    fs::write(root.join("verification.json"), verification_text).unwrap();
    fs::write(
        root.join("evidence_manifest.json"),
        to_b1_cdrive_production_preparation_commission_proposal_evidence_manifest_machine_form(
            &manifest,
        )
        .unwrap(),
    )
    .unwrap();
}

fn temporary_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cantor_b1pcp_{label}_{}", std::process::id()))
}
