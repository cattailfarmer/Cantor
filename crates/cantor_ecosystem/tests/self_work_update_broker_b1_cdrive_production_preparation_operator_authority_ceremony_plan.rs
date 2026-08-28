use std::fs;
use std::path::{Path, PathBuf};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::{
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY, B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_STATUS,
    B1CDriveOperatorAuthorityCeremonyEffectAccount,
    B1CDriveOperatorAuthorityCeremonyEvidenceArtifact,
    B1CDriveOperatorAuthorityCeremonyEvidenceManifest, B1CDriveOperatorAuthorityCeremonyFaultCode,
    B1CDriveOperatorAuthorityCeremonyRoleKind, B1CDriveOperatorAuthorityCeremonyStageKind,
    b1_cdrive_operator_authority_ceremony_evidence_manifest_digest,
    b1_cdrive_operator_authority_ceremony_plan_digest,
    b1_cdrive_operator_authority_ceremony_request_digest,
    canonical_b1_cdrive_operator_authority_ceremony_request,
    compile_b1_cdrive_operator_authority_ceremony_evidence_verification,
    compile_b1_cdrive_operator_authority_ceremony_plan,
    expected_b1_cdrive_operator_authority_ceremony_roles,
    expected_b1_cdrive_operator_authority_ceremony_stages,
    expected_b1_cdrive_operator_authority_ceremony_unresolved_authorities,
    from_b1_cdrive_operator_authority_ceremony_plan_machine_form,
    from_b1_cdrive_operator_authority_ceremony_request_machine_form,
    to_b1_cdrive_operator_authority_ceremony_evidence_manifest_machine_form,
    to_b1_cdrive_operator_authority_ceremony_evidence_verification_machine_form,
    to_b1_cdrive_operator_authority_ceremony_plan_machine_form,
    to_b1_cdrive_operator_authority_ceremony_request_machine_form,
    to_b1_cdrive_operator_authority_ceremony_verification_machine_form,
    verify_b1_cdrive_operator_authority_ceremony_evidence_directory,
    verify_b1_cdrive_operator_authority_ceremony_plan,
};

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

#[test]
fn exact_plan_and_verification_are_deterministic_and_zero_effect() {
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    let first = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();
    let second = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.authority,
        B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_AUTHORITY
    );
    assert_eq!(first.status, B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_STATUS);
    assert_eq!(
        first.effect_account,
        B1CDriveOperatorAuthorityCeremonyEffectAccount::default()
    );
    assert!(first.fixture_only);
    assert!(!first.policy_governance_proved);
    assert!(!first.live_authorization_admitted);
    assert!(!first.physical_preparation_authorized);

    let verification = verify_b1_cdrive_operator_authority_ceremony_plan(&request, &first).unwrap();
    assert_eq!(verification.role_count, 8);
    assert_eq!(verification.stage_count, 9);
    assert_eq!(verification.unresolved_authority_count, 9);
    assert_eq!(verification.deterministic_replay_count, 2);
    assert!(verification.byte_identical);
    assert_eq!(
        to_b1_cdrive_operator_authority_ceremony_verification_machine_form(
            &request,
            &first,
            &verification
        )
        .unwrap(),
        serde_json::to_string(&verification).unwrap()
    );
}

#[test]
fn exact_roles_stages_and_authorities_are_closed() {
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    let plan = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();
    assert_eq!(
        plan.roles,
        expected_b1_cdrive_operator_authority_ceremony_roles()
    );
    assert_eq!(
        plan.stages,
        expected_b1_cdrive_operator_authority_ceremony_stages()
    );
    assert_eq!(
        plan.unresolved_authorities,
        expected_b1_cdrive_operator_authority_ceremony_unresolved_authorities()
    );
    assert_eq!(
        plan.roles.iter().map(|role| role.kind).collect::<Vec<_>>(),
        vec![
            B1CDriveOperatorAuthorityCeremonyRoleKind::OperatorPrincipal,
            B1CDriveOperatorAuthorityCeremonyRoleKind::PolicyGovernor,
            B1CDriveOperatorAuthorityCeremonyRoleKind::KeyCustodian,
            B1CDriveOperatorAuthorityCeremonyRoleKind::RevocationAuthority,
            B1CDriveOperatorAuthorityCeremonyRoleKind::TimeWitness,
            B1CDriveOperatorAuthorityCeremonyRoleKind::ObservationAcquirer,
            B1CDriveOperatorAuthorityCeremonyRoleKind::PermitIssuer,
            B1CDriveOperatorAuthorityCeremonyRoleKind::BrokerExecutor,
        ]
    );
    assert_eq!(plan.stages[0].predecessor_sequence, None);
    for (index, stage) in plan.stages.iter().enumerate().skip(1) {
        assert_eq!(stage.predecessor_sequence, Some(index as u8));
    }
    assert!(plan.stages.iter().all(|stage| !stage.executed));
}

#[test]
fn strict_machine_forms_round_trip_and_duplicate_property_refuses() {
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    let request_form =
        to_b1_cdrive_operator_authority_ceremony_request_machine_form(&request).unwrap();
    assert_eq!(
        from_b1_cdrive_operator_authority_ceremony_request_machine_form(&request_form).unwrap(),
        request
    );
    let duplicated = request_form.replacen(
        "{",
        r#"{"profile":"cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan-request/0.1","#,
        1,
    );
    assert!(from_b1_cdrive_operator_authority_ceremony_request_machine_form(&duplicated).is_err());

    let plan = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();
    let plan_form =
        to_b1_cdrive_operator_authority_ceremony_plan_machine_form(&request, &plan).unwrap();
    assert_eq!(
        from_b1_cdrive_operator_authority_ceremony_plan_machine_form(&request, &plan_form).unwrap(),
        plan
    );
}

#[test]
fn lineage_and_request_ceiling_mutations_refuse_after_redigest() {
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    for mutate in [0_u8, 1, 2, 3, 4] {
        let mut changed = request.clone();
        match mutate {
            0 => changed.branch = "main".to_owned(),
            1 => changed.proposal_raw_bytes += 1,
            2 => changed.maximum_attempts = 2,
            3 => changed.automatic_retry_count = 1,
            4 => changed.fixture_only = false,
            _ => unreachable!(),
        }
        changed.request_sha256 = empty_digest();
        changed.request_sha256 =
            b1_cdrive_operator_authority_ceremony_request_digest(&changed).unwrap();
        assert!(compile_b1_cdrive_operator_authority_ceremony_plan(&changed).is_err());
    }
}

#[test]
fn role_stage_and_dependency_mutations_refuse_after_redigest() {
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    let plan = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();

    let mut role = plan.clone();
    role.roles[0].kind = B1CDriveOperatorAuthorityCeremonyRoleKind::PolicyGovernor;
    redigest_plan(&mut role);
    assert!(verify_b1_cdrive_operator_authority_ceremony_plan(&request, &role).is_err());

    let mut stage = plan.clone();
    stage.stages.swap(0, 1);
    redigest_plan(&mut stage);
    assert!(verify_b1_cdrive_operator_authority_ceremony_plan(&request, &stage).is_err());

    let mut edge = plan.clone();
    edge.stages[4].predecessor_sequence = Some(2);
    redigest_plan(&mut edge);
    assert!(verify_b1_cdrive_operator_authority_ceremony_plan(&request, &edge).is_err());

    let mut executed = plan.clone();
    executed.stages[8].executed = true;
    redigest_plan(&mut executed);
    assert!(verify_b1_cdrive_operator_authority_ceremony_plan(&request, &executed).is_err());
}

#[test]
fn authority_fixture_and_effect_laundering_refuse_after_redigest() {
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    let plan = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();

    let mut authority = plan.clone();
    authority.policy_governance_proved = true;
    redigest_plan(&mut authority);
    let fault =
        verify_b1_cdrive_operator_authority_ceremony_plan(&request, &authority).unwrap_err();
    assert_eq!(
        fault.code,
        B1CDriveOperatorAuthorityCeremonyFaultCode::Authority
    );

    let mut fixture = plan.clone();
    fixture.fixture_only = false;
    redigest_plan(&mut fixture);
    assert!(verify_b1_cdrive_operator_authority_ceremony_plan(&request, &fixture).is_err());

    let mut effect = plan.clone();
    effect.effect_account.signing_count = 1;
    redigest_plan(&mut effect);
    let fault = verify_b1_cdrive_operator_authority_ceremony_plan(&request, &effect).unwrap_err();
    assert_eq!(
        fault.code,
        B1CDriveOperatorAuthorityCeremonyFaultCode::Effect
    );
}

#[test]
fn each_ceremony_stage_requires_exactly_one_named_external_authority() {
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    let plan = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();
    assert!(
        plan.stages
            .iter()
            .all(|stage| stage.authority_required.len() == 1)
    );
    assert_eq!(
        plan.stages
            .iter()
            .map(|stage| stage.kind)
            .collect::<Vec<_>>(),
        vec![
            B1CDriveOperatorAuthorityCeremonyStageKind::PolicyGovernance,
            B1CDriveOperatorAuthorityCeremonyStageKind::PublicKeyCustody,
            B1CDriveOperatorAuthorityCeremonyStageKind::RevocationTruth,
            B1CDriveOperatorAuthorityCeremonyStageKind::CurrentTimeWitness,
            B1CDriveOperatorAuthorityCeremonyStageKind::LiveDecision,
            B1CDriveOperatorAuthorityCeremonyStageKind::CryptographicCorrespondence,
            B1CDriveOperatorAuthorityCeremonyStageKind::FreshObservation,
            B1CDriveOperatorAuthorityCeremonyStageKind::PrivateExecutionPermit,
            B1CDriveOperatorAuthorityCeremonyStageKind::BrokerProjectionAdmission,
        ]
    );
}

#[test]
fn production_module_has_no_ceremony_execution_surface() {
    let source = fs::read_to_string(source_path()).unwrap();
    for forbidden in [
        "SigningKey",
        "Signer",
        "SystemTime",
        "std::process",
        "std::net",
        "std::env",
        "std::fs",
        "Command::",
        "OpenOptions",
        "TcpStream",
        "production_broker(",
    ] {
        assert!(
            !source.contains(forbidden),
            "production source contains forbidden surface {forbidden}"
        );
    }
}

#[test]
fn independent_evidence_replays_exact_fixture_and_refuses_extra_entry() {
    let root = synthetic_root("valid");
    write_fixture(&root);
    let verified = verify_b1_cdrive_operator_authority_ceremony_evidence_directory(&root).unwrap();
    assert_eq!(verified.artifact_count, 3);
    assert_eq!(verified.independent_replay_count, 2);
    assert!(verified.byte_identical_replays);
    assert!(verified.fixture_only);
    assert!(!verified.live_authorization_admitted);
    assert_eq!(
        verified.effect_account,
        B1CDriveOperatorAuthorityCeremonyEffectAccount::default()
    );
    fs::write(root.join("extra.json"), "{}").unwrap();
    assert!(verify_b1_cdrive_operator_authority_ceremony_evidence_directory(&root).is_err());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn independent_evidence_refuses_raw_plan_and_manifest_tamper() {
    let root = synthetic_root("tamper");
    write_fixture(&root);
    let plan_path = root.join("plan.json");
    let mut plan = fs::read(&plan_path).unwrap();
    plan.push(b' ');
    fs::write(&plan_path, plan).unwrap();
    assert!(verify_b1_cdrive_operator_authority_ceremony_evidence_directory(&root).is_err());
    fs::remove_dir_all(&root).unwrap();

    let root = synthetic_root("manifest");
    write_fixture(&root);
    let manifest_path = root.join("evidence_manifest.json");
    let text = fs::read_to_string(&manifest_path).unwrap();
    fs::write(
        &manifest_path,
        text.replacen("\"fixture_only\":true", "\"fixture_only\":false", 1),
    )
    .unwrap();
    assert!(verify_b1_cdrive_operator_authority_ceremony_evidence_directory(&root).is_err());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_operator_authority_ceremony_evidence() {
    let root = std::env::var_os("CANTOR_B1OACP_EVIDENCE_DIR")
        .map(PathBuf::from)
        .expect("CANTOR_B1OACP_EVIDENCE_DIR is required");
    assert!(!root.exists(), "owned evidence root must be absent");
    write_fixture(&root);
    verify_b1_cdrive_operator_authority_ceremony_evidence_directory(&root).unwrap();
}

fn redigest_plan(plan: &mut cantor_ecosystem::B1CDriveOperatorAuthorityCeremonyPlan) {
    plan.plan_sha256 = empty_digest();
    plan.plan_sha256 = b1_cdrive_operator_authority_ceremony_plan_digest(plan).unwrap();
}

fn source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "src/self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan.rs",
    )
}

fn synthetic_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cantor_b1oacp_{}_{}", std::process::id(), label))
}

fn write_fixture(root: &Path) {
    assert!(!root.exists());
    fs::create_dir_all(root).unwrap();
    let request = canonical_b1_cdrive_operator_authority_ceremony_request().unwrap();
    let plan = compile_b1_cdrive_operator_authority_ceremony_plan(&request).unwrap();
    let verification = verify_b1_cdrive_operator_authority_ceremony_plan(&request, &plan).unwrap();
    let request_text =
        to_b1_cdrive_operator_authority_ceremony_request_machine_form(&request).unwrap();
    let plan_text =
        to_b1_cdrive_operator_authority_ceremony_plan_machine_form(&request, &plan).unwrap();
    let verification_text = to_b1_cdrive_operator_authority_ceremony_verification_machine_form(
        &request,
        &plan,
        &verification,
    )
    .unwrap();
    let artifacts = [
        ("plan.json", plan_text.as_bytes()),
        ("request.json", request_text.as_bytes()),
        ("verification.json", verification_text.as_bytes()),
    ];
    for (name, bytes) in artifacts {
        fs::write(root.join(name), bytes).unwrap();
    }
    let mut manifest = B1CDriveOperatorAuthorityCeremonyEvidenceManifest {
        profile: cantor_ecosystem::B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_EVIDENCE_MANIFEST_PROFILE
            .to_owned(),
        source_snapshot_uuid:
            cantor_ecosystem::B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: cantor_ecosystem::B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_CANONICAL_UUID
            .to_owned(),
        signature_uuid: cantor_ecosystem::B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_SIGNATURE_UUID
            .to_owned(),
        formation_commit: cantor_ecosystem::B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_FORMATION_COMMIT
            .to_owned(),
        artifacts: artifacts
            .into_iter()
            .map(
                |(path, bytes)| B1CDriveOperatorAuthorityCeremonyEvidenceArtifact {
                    path: path.to_owned(),
                    bytes: bytes.len() as u64,
                    sha256: sha256_bytes(bytes),
                },
            )
            .collect(),
        fixture_only: true,
        physical_execution_authorized: false,
        non_authority_statement:
            cantor_ecosystem::B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_NON_AUTHORITY.to_owned(),
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 =
        b1_cdrive_operator_authority_ceremony_evidence_manifest_digest(&manifest).unwrap();
    let manifest_text =
        to_b1_cdrive_operator_authority_ceremony_evidence_manifest_machine_form(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), manifest_text).unwrap();

    let evidence = compile_b1_cdrive_operator_authority_ceremony_evidence_verification(
        &request,
        &plan,
        &verification,
    )
    .unwrap();
    assert!(
        !to_b1_cdrive_operator_authority_ceremony_evidence_verification_machine_form(&evidence)
            .unwrap()
            .is_empty()
    );
}
