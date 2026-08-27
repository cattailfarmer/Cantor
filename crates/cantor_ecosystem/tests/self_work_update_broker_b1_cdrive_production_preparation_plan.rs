use std::{
    fs,
    path::{Path, PathBuf},
};

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::{
    B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT, B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_MANIFEST_PROFILE,
    B1_CDRIVE_PRODUCTION_PREPARATION_FORMATION_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_MINIMUM_FREE_BYTES,
    B1_CDRIVE_PRODUCTION_PREPARATION_OBSERVED_FREE_BYTES,
    B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_AUTHORITY,
    B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_REQUEST_PROFILE,
    B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_STATUS, B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID,
    B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_CUSTODY_COMMIT,
    B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID,
    B1CDriveProductionPreparationEffectClass, B1CDriveProductionPreparationEvidenceArtifact,
    B1CDriveProductionPreparationEvidenceManifest, B1CDriveProductionPreparationFaultCode,
    B1CDriveProductionPreparationPlan, B1CDriveProductionPreparationPlanRequest,
    b1_cdrive_production_preparation_evidence_manifest_digest,
    b1_cdrive_production_preparation_plan_digest, b1_cdrive_production_preparation_request_digest,
    compile_b1_cdrive_production_preparation_evidence_verification,
    compile_b1_cdrive_production_preparation_plan,
    expected_b1_cdrive_production_preparation_build_junctions,
    expected_b1_cdrive_production_preparation_upstream_identities,
    from_b1_cdrive_production_preparation_plan_machine_form,
    from_b1_cdrive_production_preparation_request_machine_form,
    to_b1_cdrive_production_preparation_evidence_manifest_machine_form,
    to_b1_cdrive_production_preparation_evidence_verification_machine_form,
    to_b1_cdrive_production_preparation_plan_machine_form,
    to_b1_cdrive_production_preparation_request_machine_form,
    validate_b1_cdrive_production_preparation_plan,
    verify_b1_cdrive_production_preparation_evidence_directory,
};

const NAMESPACE: &str = "cf39b696-21e1-41c4-b382-b68606515f89";

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn fixture_request() -> B1CDriveProductionPreparationPlanRequest {
    let mut request = B1CDriveProductionPreparationPlanRequest {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_REQUEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID.to_owned(),
        source_custody_commit: B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_CUSTODY_COMMIT.to_owned(),
        production_broker_implementation_commit: B1_CDRIVE_PRODUCTION_BROKER_IMPLEMENTATION_COMMIT
            .to_owned(),
        production_broker_bookend_commit: B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT.to_owned(),
        expected_current_commit: B1_CDRIVE_PRODUCTION_BROKER_BOOKEND_COMMIT.to_owned(),
        branch: "codex/self-hosted-corpus".to_owned(),
        canonical_remote: "https://github.com/cattailfarmer/Cantor".to_owned(),
        working_project: r"C:\Project\Cantor".to_owned(),
        observed_cdrive_free_bytes: B1_CDRIVE_PRODUCTION_PREPARATION_OBSERVED_FREE_BYTES,
        minimum_cdrive_free_bytes: B1_CDRIVE_PRODUCTION_PREPARATION_MINIMUM_FREE_BYTES,
        build_junctions: expected_b1_cdrive_production_preparation_build_junctions(),
        upstream_identities: expected_b1_cdrive_production_preparation_upstream_identities(),
        plan_namespace_uuid: NAMESPACE.to_owned(),
        provider_available: false,
        request_sha256: empty_digest(),
    };
    request.request_sha256 = b1_cdrive_production_preparation_request_digest(&request).unwrap();
    request
}

fn redigest_plan(plan: &mut B1CDriveProductionPreparationPlan) {
    plan.plan_sha256 = empty_digest();
    plan.plan_sha256 = b1_cdrive_production_preparation_plan_digest(plan).unwrap();
}

#[test]
fn valid_plan_is_deterministic_closed_and_zero_effect() {
    let request = fixture_request();
    let first = compile_b1_cdrive_production_preparation_plan(&request).unwrap();
    let second = compile_b1_cdrive_production_preparation_plan(&request).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.status, B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_STATUS);
    assert_eq!(
        first.authority,
        B1_CDRIVE_PRODUCTION_PREPARATION_PLAN_AUTHORITY
    );
    assert_eq!(first.roles.len(), 5);
    assert_eq!(first.operations.len(), 12);
    assert_eq!(first.unresolved_authorities.len(), 10);
    assert!(!first.physical_preparation_authorized);
    assert!(
        first
            .operations
            .iter()
            .skip(5)
            .take(6)
            .all(|operation| operation.effect_class
                == B1CDriveProductionPreparationEffectClass::PlannedEffect
                && operation.later_authority_required)
    );
}

#[test]
fn request_and_plan_machine_forms_round_trip_exactly() {
    let request = fixture_request();
    let request_text = to_b1_cdrive_production_preparation_request_machine_form(&request).unwrap();
    assert_eq!(
        from_b1_cdrive_production_preparation_request_machine_form(&request_text).unwrap(),
        request
    );
    let plan = compile_b1_cdrive_production_preparation_plan(&request).unwrap();
    let plan_text = to_b1_cdrive_production_preparation_plan_machine_form(&request, &plan).unwrap();
    assert_eq!(
        from_b1_cdrive_production_preparation_plan_machine_form(&request, &plan_text).unwrap(),
        plan
    );
    assert!(
        from_b1_cdrive_production_preparation_request_machine_form(&(request_text.clone() + "\n"))
            .is_err()
    );
    let duplicate = request_text.replacen(
        "{\"profile\":",
        "{\"profile\":\"duplicate\",\"profile\":",
        1,
    );
    assert!(from_b1_cdrive_production_preparation_request_machine_form(&duplicate).is_err());
}

#[test]
fn request_identity_capacity_junction_upstream_and_provider_drift_refuse() {
    let base = fixture_request();
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.observed_cdrive_free_bytes = B1_CDRIVE_PRODUCTION_PREPARATION_MINIMUM_FREE_BYTES - 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.provider_available = true;
    variants.push(changed);
    let mut changed = base.clone();
    changed.build_junctions[0].target.push_str("-drift");
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream_identities.swap(0, 1);
    variants.push(changed);
    let mut changed = base.clone();
    changed.expected_current_commit = "0".repeat(40);
    variants.push(changed);
    let mut changed = base.clone();
    changed.plan_namespace_uuid = B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned();
    variants.push(changed);
    for mut variant in variants {
        variant.request_sha256 = empty_digest();
        variant.request_sha256 = b1_cdrive_production_preparation_request_digest(&variant).unwrap();
        assert!(compile_b1_cdrive_production_preparation_plan(&variant).is_err());
    }
}

#[test]
fn role_operation_unresolved_and_effect_mutations_refuse_even_when_redigested() {
    let request = fixture_request();
    let plan = compile_b1_cdrive_production_preparation_plan(&request).unwrap();
    let mut variants = Vec::new();
    let mut changed = plan.clone();
    changed.roles[1].path = r"D:\candidate".to_owned();
    variants.push(changed);
    let mut changed = plan.clone();
    changed.operations.swap(0, 1);
    variants.push(changed);
    let mut changed = plan.clone();
    changed.unresolved_authorities.remove(0);
    variants.push(changed);
    let mut changed = plan.clone();
    changed.effect_account.process_count = 1;
    variants.push(changed);
    let mut changed = plan.clone();
    changed.physical_preparation_authorized = true;
    variants.push(changed);
    for mut variant in variants {
        redigest_plan(&mut variant);
        assert!(validate_b1_cdrive_production_preparation_plan(&request, &variant).is_err());
    }
}

#[test]
fn retained_evidence_replays_independently_without_effects() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../experiments/self_work_update_broker_b1_cdrive_production_preparation_plan_p0/implementation_provider_free_evidence");
    let left = verify_b1_cdrive_production_preparation_evidence_directory(&root).unwrap();
    let right = verify_b1_cdrive_production_preparation_evidence_directory(&root).unwrap();
    assert_eq!(left, right);
    assert_eq!(left.independent_replay_count, 2);
    assert!(left.byte_identical_replays);
    assert!(!left.physical_preparation_authorized);
}

#[test]
fn evidence_refuses_extra_and_raw_byte_tamper() {
    let root = temporary_root("tamper");
    write_evidence(&root);
    fs::write(root.join("extra.json"), b"{}").unwrap();
    assert!(verify_b1_cdrive_production_preparation_evidence_directory(&root).is_err());
    fs::remove_file(root.join("extra.json")).unwrap();
    let mut request = fs::read(root.join("request.json")).unwrap();
    request.push(b'\n');
    fs::write(root.join("request.json"), request).unwrap();
    assert!(verify_b1_cdrive_production_preparation_evidence_directory(&root).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn formation_and_effect_surfaces_remain_statically_locked() {
    let plan_source =
        include_str!("../src/self_work_update_broker_b1_cdrive_production_preparation_plan.rs");
    let evidence_source = include_str!(
        "../src/self_work_update_broker_b1_cdrive_production_preparation_plan_evidence.rs"
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
            !plan_source.contains(forbidden),
            "plan effect surface: {forbidden}"
        );
    }
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
            !evidence_source.contains(forbidden),
            "verifier effect surface: {forbidden}"
        );
    }
    assert!(include_str!("../../../narrative/registries/Cantor_Self_Work_Update_Broker_B1_CDrive_Production_Preparation_Plan_P0_Satisfaction_Signature.sop").contains(B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID));
}

#[test]
fn fault_codes_distinguish_identity_from_plan_order() {
    let mut request = fixture_request();
    request.provider_available = true;
    request.request_sha256 = empty_digest();
    request.request_sha256 = b1_cdrive_production_preparation_request_digest(&request).unwrap();
    assert_eq!(
        compile_b1_cdrive_production_preparation_plan(&request)
            .unwrap_err()
            .code,
        B1CDriveProductionPreparationFaultCode::Identity
    );
    let request = fixture_request();
    let mut plan = compile_b1_cdrive_production_preparation_plan(&request).unwrap();
    plan.operations.swap(0, 1);
    redigest_plan(&mut plan);
    assert_eq!(
        validate_b1_cdrive_production_preparation_plan(&request, &plan)
            .unwrap_err()
            .code,
        B1CDriveProductionPreparationFaultCode::Order
    );
}

#[test]
#[ignore = "writes only the explicitly supplied owned evidence root"]
fn write_owned_provider_free_production_preparation_plan_evidence() {
    let root = std::env::var_os("CANTOR_B1PP_EVIDENCE_ROOT")
        .map(PathBuf::from)
        .expect("CANTOR_B1PP_EVIDENCE_ROOT");
    assert!(!root.exists(), "owned evidence root must be absent");
    write_evidence(&root);
}

fn write_evidence(root: &Path) {
    fs::create_dir(root).unwrap();
    let request = fixture_request();
    let plan = compile_b1_cdrive_production_preparation_plan(&request).unwrap();
    let verification =
        compile_b1_cdrive_production_preparation_evidence_verification(&request, &plan).unwrap();
    let request_text = to_b1_cdrive_production_preparation_request_machine_form(&request).unwrap();
    let plan_text = to_b1_cdrive_production_preparation_plan_machine_form(&request, &plan).unwrap();
    let verification_text =
        to_b1_cdrive_production_preparation_evidence_verification_machine_form(&verification)
            .unwrap();
    let artifacts = [
        ("plan.json", plan_text.as_bytes()),
        ("request.json", request_text.as_bytes()),
        ("verification.json", verification_text.as_bytes()),
    ]
    .into_iter()
    .map(
        |(path, bytes)| B1CDriveProductionPreparationEvidenceArtifact {
            path: path.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(bytes),
        },
    )
    .collect();
    let mut manifest = B1CDriveProductionPreparationEvidenceManifest {
        profile: B1_CDRIVE_PRODUCTION_PREPARATION_EVIDENCE_MANIFEST_PROFILE.to_owned(),
        source_snapshot_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_CANONICAL_UUID.to_owned(),
        signature_uuid: B1_CDRIVE_PRODUCTION_PREPARATION_SIGNATURE_UUID.to_owned(),
        formation_commit: B1_CDRIVE_PRODUCTION_PREPARATION_FORMATION_COMMIT.to_owned(),
        artifacts,
        physical_execution_authorized: false,
        non_authority_statement: "Provider-free supplied-data plan evidence only; no live observation, physical preparation, external scratch, worktree, ref, evidence, lease, ledger, Phase3A, commission, process, provider, model, writer, persistence, activation, D-drive runtime contact, cleanup, or foreign effect.".to_owned(),
        manifest_sha256: empty_digest(),
    };
    manifest.manifest_sha256 =
        b1_cdrive_production_preparation_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("request.json"), request_text).unwrap();
    fs::write(root.join("plan.json"), plan_text).unwrap();
    fs::write(root.join("verification.json"), verification_text).unwrap();
    fs::write(
        root.join("evidence_manifest.json"),
        to_b1_cdrive_production_preparation_evidence_manifest_machine_form(&manifest).unwrap(),
    )
    .unwrap();
}

fn temporary_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cantor_b1pp_{label}_{}", std::process::id()))
}
