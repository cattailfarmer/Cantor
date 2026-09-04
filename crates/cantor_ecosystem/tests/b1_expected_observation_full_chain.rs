//! Full A6 replay and adversaries; test-only fixed keys never enter production.
#[path = "support/eocv_predecessor_fixture.rs"]
mod upstream_fixture;
use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
const CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-expected-observation-verify");
const EVIDENCE_CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-expected-observation-evidence-verify");
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn empty() -> ContentDigest {
    sha256_bytes(b"")
}
fn temporary(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cantor-eocv-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}
fn line<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
fn raw_line(value: &[u8]) -> Vec<u8> {
    let mut bytes = value.to_vec();
    bytes.push(b'\n');
    bytes
}
fn change_typed<T: Serialize + DeserializeOwned>(original: &T, field: &str, value: Value) -> T {
    let mut object = serde_json::to_value(original).unwrap();
    object[field] = value;
    serde_json::from_value(object).unwrap()
}
#[derive(Clone)]
struct Fixture {
    a5: upstream_fixture::Fixture,
    a5_receipt: OdcvVerificationReceipt,
    plan_request: B1CDriveProductionPreparationPlanRequest,
    plan: B1CDriveProductionPreparationPlan,
    raw_plan_request: Vec<u8>,
    raw_plan: Vec<u8>,
    bundle: EocvObservationBundle,
    raw_bundle: Vec<u8>,
    request: EocvVerificationRequest,
}
impl Fixture {
    fn new() -> Self {
        let a5 = upstream_fixture::fixture_for(
            KcvInputClass::DeterministicFixtureCandidate,
            B1CDriveOperatorDecisionKind::Authorize,
        );
        let a5_receipt = a5.verify().unwrap();
        let raw_plan_request=include_str!("../../../experiments/self_work_update_broker_b1_cdrive_production_preparation_plan_p0/implementation_provider_free_evidence/request.json").trim_end_matches('\n').as_bytes().to_vec();
        let plan_request = from_b1_cdrive_production_preparation_request_machine_form(
            std::str::from_utf8(&raw_plan_request).unwrap(),
        )
        .unwrap();
        let plan = compile_b1_cdrive_production_preparation_plan(&plan_request).unwrap();
        let raw_plan = to_b1_cdrive_production_preparation_plan_machine_form(&plan_request, &plan)
            .unwrap()
            .into_bytes();
        let proposal = from_b1_cdrive_production_preparation_commission_proposal_machine_form(
            &canonical_b1_cdrive_production_preparation_commission_proposal_request().unwrap(),
            &a5.legacy_request.proposal_machine_form,
        )
        .unwrap();
        let bundle = EocvObservationBundle {
            profile: EOCV_BUNDLE_PROFILE.to_owned(),
            bundle_uuid: "a6000000-0000-4000-8000-000000000001".to_owned(),
            a5_receipt_sha256: a5_receipt.receipt_sha256.clone(),
            expected_carrier_commit: "f".repeat(40),
            observed_carrier_commit: "f".repeat(40),
            observed_branch: plan_request.branch.clone(),
            observed_remote: plan_request.canonical_remote.clone(),
            observed_project: plan_request.working_project.clone(),
            observed_unix_ms: a5_receipt.observed_unix_ms,
            observed_cdrive_free_bytes: plan_request.minimum_cdrive_free_bytes,
            build_junctions: plan_request
                .build_junctions
                .iter()
                .map(|j| EocvJunctionObservation {
                    source: j.source.clone(),
                    kind: EocvJunctionKind::Junction,
                    target: Some(j.target.clone()),
                })
                .collect(),
            upstream_identities: plan_request.upstream_identities.clone(),
            role_observations: plan
                .roles
                .iter()
                .map(|r| EocvRoleObservation {
                    kind: r.kind,
                    path: r.path.clone(),
                    state: EocvPresenceAssertion::Absent,
                })
                .collect(),
            reserved_ref_observation: EocvReservedRefObservation {
                reference: proposal.proposed_ref,
                state: EocvPresenceAssertion::Absent,
            },
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            evidence_references: vec!["opaque:fixture-supplied-not-collected".to_owned()],
            bundle_sha256: empty(),
        };
        let request = EocvVerificationRequest {
            profile: EOCV_REQUEST_PROFILE.to_owned(),
            source_snapshot_uuid: EOCV_SOURCE_SNAPSHOT_UUID.to_owned(),
            canonical_uuid: EOCV_CANONICAL_UUID.to_owned(),
            signature_uuid: EOCV_SIGNATURE_UUID.to_owned(),
            source_custody_commit: EOCV_SOURCE_CUSTODY_COMMIT.to_owned(),
            formation_commit: EOCV_FORMATION_COMMIT.to_owned(),
            formation_bookend_commit: EOCV_FORMATION_BOOKEND_COMMIT.to_owned(),
            a5_implementation_commit: EOCV_A5_IMPLEMENTATION_COMMIT.to_owned(),
            a5_bookend_commit: EOCV_A5_BOOKEND_COMMIT.to_owned(),
            a5_proof_uuid: EOCV_A5_PROOF_UUID.to_owned(),
            plan_implementation_commit: EOCV_PLAN_IMPLEMENTATION_COMMIT.to_owned(),
            plan_bookend_commit: EOCV_PLAN_BOOKEND_COMMIT.to_owned(),
            plan_proof_uuid: EOCV_PLAN_PROOF_UUID.to_owned(),
            a5_verification_request_sha256: empty(),
            a5_receipt_sha256: empty(),
            preparation_plan_request_raw_sha256: empty(),
            preparation_plan_request_sha256: empty(),
            preparation_plan_raw_sha256: empty(),
            preparation_plan_sha256: empty(),
            authority_packet_request_sha256: empty(),
            authority_packet_sha256: empty(),
            a6_descriptor_sha256: empty(),
            observation_bundle_raw_sha256: empty(),
            request_sha256: empty(),
            authority_packet_request: a5.request.authority_packet_request.clone(),
            a6_candidate_uuid: a5.request.authority_packet_request.descriptors[5]
                .candidate_uuid
                .clone(),
            observation_bundle_bytes: 1,
            expected_bundle_uuid: bundle.bundle_uuid.clone(),
            expected_carrier_commit: bundle.expected_carrier_commit.clone(),
            input_class: bundle.input_class,
            evidence_references: vec!["opaque:A6-request".to_owned()],
            maximum_attempts: 1,
            automatic_retry_count: 0,
            automatic_cleanup_count: 0,
        };
        let mut f = Self {
            a5,
            a5_receipt,
            plan_request,
            plan,
            raw_plan_request,
            raw_plan,
            bundle,
            raw_bundle: vec![],
            request,
        };
        f.bind();
        f
    }
    fn predecessor(&self) -> EocvPredecessor<'_> {
        EocvPredecessor {
            upstream: self.a5.predecessor(),
            a5_policy: &self.a5.policy,
            a5_legacy_request: &self.a5.legacy_request,
            raw_a5_envelope: &self.a5.raw_envelope,
            a5_request: &self.a5.request,
            a5_receipt: &self.a5_receipt,
        }
    }
    fn verify(&self) -> Result<EocvVerificationReceipt, EocvFault> {
        verify_eocv_expected_observation(
            &self.request,
            &self.predecessor(),
            &self.raw_plan_request,
            &self.raw_plan,
            &self.raw_bundle,
        )
    }
    fn validate(&self, receipt: &EocvVerificationReceipt) -> Result<(), EocvFault> {
        validate_eocv_receipt(
            &self.request,
            &self.predecessor(),
            &self.raw_plan_request,
            &self.raw_plan,
            &self.raw_bundle,
            receipt,
        )
    }
    fn redigest_packet(&mut self) {
        for d in &mut self.request.authority_packet_request.descriptors {
            d.descriptor_sha256 = b1oapr_descriptor_digest(d).unwrap();
        }
        self.request.a6_descriptor_sha256 = self.request.authority_packet_request.descriptors[5]
            .descriptor_sha256
            .clone();
        self.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&self.request.authority_packet_request).unwrap();
        self.request.authority_packet_request_sha256 =
            self.request.authority_packet_request.request_sha256.clone();
        if let Ok(packet) = compile_b1oapr_packet(&self.request.authority_packet_request) {
            self.request.authority_packet_sha256 = packet.packet_sha256;
        }
        self.request.request_sha256 = eocv_request_digest(&self.request).unwrap();
    }
    fn bind_raw_bundle(&mut self) {
        let d = &mut self.request.authority_packet_request.descriptors[5];
        d.declared_bytes = self.raw_bundle.len() as u64;
        d.content_sha256 = sha256_bytes(&self.raw_bundle);
        d.fixture_only = self.request.input_class == KcvInputClass::DeterministicFixtureCandidate;
        d.origin = if d.fixture_only {
            B1OaprCandidateOrigin::DeterministicFixtureCandidate
        } else {
            B1OaprCandidateOrigin::ExternallySuppliedCandidate
        };
        self.request.observation_bundle_bytes = d.declared_bytes;
        self.request.observation_bundle_raw_sha256 = d.content_sha256.clone();
        self.redigest_packet();
    }
    fn bind(&mut self) {
        self.a5_receipt = self.a5.verify().unwrap();
        self.request.a5_verification_request_sha256 = self.a5.request.request_sha256.clone();
        self.request.a5_receipt_sha256 = self.a5_receipt.receipt_sha256.clone();
        self.bundle.a5_receipt_sha256 = self.a5_receipt.receipt_sha256.clone();
        self.request.authority_packet_request = self.a5.request.authority_packet_request.clone();
        self.request.preparation_plan_request_raw_sha256 = sha256_bytes(&self.raw_plan_request);
        self.request.preparation_plan_request_sha256 = self.plan_request.request_sha256.clone();
        self.request.preparation_plan_raw_sha256 = sha256_bytes(&self.raw_plan);
        self.request.preparation_plan_sha256 = self.plan.plan_sha256.clone();
        self.bundle.bundle_sha256 = eocv_bundle_digest(&self.bundle).unwrap();
        self.raw_bundle = serde_json::to_vec(&self.bundle).unwrap();
        self.bind_raw_bundle();
    }
}
fn write_evidence(root: &Path, f: &Fixture) {
    fs::create_dir(root).expect("fresh caller-owned output");
    let receipt = f.verify().unwrap();
    let a = &f.a5;
    let payloads = [
        line(&a.predecessor_request),
        line(&a.predecessor_packet),
        line(&a.predecessor_verification),
        raw_line(&a.raw_a1),
        line(&a.a1_request),
        line(&a.a1_receipt),
        raw_line(&a.raw_a2),
        line(&a.a2_request),
        line(&a.a2_receipt),
        raw_line(&a.raw_a3),
        line(&a.a3_request),
        line(&a.a3_receipt),
        raw_line(&a.raw_witness),
        line(&a.a4_request),
        line(&a.a4_receipt),
        line(&a.policy),
        line(&a.legacy_request),
        raw_line(&a.raw_envelope),
        line(&a.request),
        line(&f.a5_receipt),
        raw_line(&f.raw_plan_request),
        raw_line(&f.raw_plan),
        raw_line(&f.raw_bundle),
        line(&f.request),
        line(&receipt),
    ];
    let artifacts: Vec<EocvEvidenceArtifact> = payloads
        .iter()
        .zip(EOCV_EVIDENCE_FILES)
        .map(|(bytes, name)| {
            fs::write(root.join(name), bytes).unwrap();
            EocvEvidenceArtifact {
                path: name.to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_bytes(bytes),
            }
        })
        .collect();
    let mut manifest = EocvEvidenceManifest {
        profile: EOCV_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "a6000000-0000-4000-8000-000000000002".to_owned(),
        fixture_only: receipt.fixture_only,
        total_artifact_bytes: artifacts.iter().map(|a| a.bytes).sum(),
        artifacts,
        artifact_count: 25,
        retained_authority_packet_sha256: receipt.authority_packet_sha256.clone(),
        retained_a5_receipt_sha256: receipt.a5_receipt_sha256.clone(),
        retained_preparation_plan_sha256: receipt.preparation_plan_sha256.clone(),
        retained_observation_bundle_sha256: receipt.observation_bundle_sha256.clone(),
        retained_receipt_sha256: receipt.receipt_sha256.clone(),
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty(),
    };
    manifest.manifest_sha256 = eocv_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}
fn rehash_evidence(root: &Path) {
    let mut m: EocvEvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap();
    for a in &mut m.artifacts {
        let bytes = fs::read(root.join(&a.path)).unwrap();
        a.bytes = bytes.len() as u64;
        a.sha256 = sha256_bytes(&bytes);
    }
    m.total_artifact_bytes = m.artifacts.iter().map(|a| a.bytes).sum();
    m.manifest_sha256 = eocv_evidence_manifest_digest(&m).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&m)).unwrap();
}

#[test]
fn complete_chain_and_historical_pins_replay() {
    let f = Fixture::new();
    let receipt = f.verify().unwrap();
    assert_eq!(receipt.status, EOCV_MATCHED_STATUS);
    assert!(receipt.comparison_account.all_expectations_match);
    assert_eq!(receipt.a5_receipt, f.a5_receipt);
    assert_eq!(
        receipt.legacy_decision_expected_current_commit,
        "98683316ff8735026dded1838c88e84edf7288f5"
    );
    assert_eq!(
        receipt.preparation_plan_expected_current_commit,
        "49af9aa11db6696a95a13fead653c5edc1253f0d"
    );
    assert_eq!(receipt.expected_carrier_commit, "f".repeat(40));
    assert!(!receipt.execution_authorized);
    assert!(!receipt.decision_signature_binds_a6_observation);
    assert_eq!(receipt.effect_account, TwvEffectAccount::default());
    assert_eq!(f.plan_request.observed_cdrive_free_bytes, 43004325888);
    assert_eq!(receipt.minimum_cdrive_free_bytes, 15032385536);
    let text = to_eocv_receipt_machine_form(
        &f.request,
        &f.predecessor(),
        &f.raw_plan_request,
        &f.raw_plan,
        &f.raw_bundle,
        &receipt,
    )
    .unwrap();
    assert_eq!(
        from_eocv_receipt_machine_form(
            &f.request,
            &f.predecessor(),
            &f.raw_plan_request,
            &f.raw_plan,
            &f.raw_bundle,
            &text
        )
        .unwrap(),
        receipt
    );
}
#[test]
fn independent_evidence_and_fresh_processes_replay() {
    let f = Fixture::new();
    let root = temporary("replay");
    write_evidence(&root, &f);
    let replay = verify_eocv_evidence_directory(&root).unwrap();
    assert_eq!(replay.receipt, f.verify().unwrap());
    assert_eq!(replay.manifest.artifact_count, 25);
    for _ in 0..2 {
        let output = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stderr.is_empty());
        assert_eq!(
            output.stdout,
            raw_line(replay.receipt_machine_form.as_bytes())
        );
    }
    let paths: Vec<_> = EOCV_EVIDENCE_FILES[..24]
        .iter()
        .map(|n| root.join(n))
        .collect();
    assert_eq!(
        verify_eocv_payload_paths(&paths).unwrap(),
        replay.receipt_machine_form
    );
    let output = Command::new(CLI).args(&paths).output().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(
        output.stdout,
        raw_line(replay.receipt_machine_form.as_bytes())
    );
    assert!(output.stderr.is_empty());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn retained_identity_rehashed_reaches_restart_refusal() {
    let f = Fixture::new();
    let root = temporary("restart");
    write_evidence(&root, &f);
    let mut m: EocvEvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap();
    m.retained_receipt_sha256 = sha256_bytes(b"rehashed false retained identity");
    fs::write(root.join("evidence_manifest.json"), line(&m)).unwrap();
    rehash_evidence(&root);
    assert_eq!(
        verify_eocv_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::Restart
    );
    let output = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Restart"));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn upstream_classes_kinds_intervals_and_adverse_a3_survive() {
    let base = Fixture::new();
    for class in [
        KcvInputClass::DeterministicFixtureCandidate,
        KcvInputClass::ExternallySuppliedCandidate,
    ] {
        for kind in [
            B1CDriveOperatorDecisionKind::Authorize,
            B1CDriveOperatorDecisionKind::Reject,
        ] {
            let mut f = base.clone();
            f.a5 = upstream_fixture::fixture_for(class, kind);
            f.a5.signed_change(|payload| {
                payload.issued_at_unix_millis = 4;
                payload.expires_at_unix_millis = 9;
            });
            for (observed, relation) in [
                (3, OdcvIntervalRelation::BeforeDecisionInterval),
                (4, OdcvIntervalRelation::WithinDecisionInterval),
                (9, OdcvIntervalRelation::AfterDecisionInterval),
            ] {
                f.a5.set_observed(observed);
                f.bundle.observed_unix_ms = observed;
                f.bind();
                let receipt = f.verify().unwrap();
                assert_eq!(receipt.a5_receipt.comparison_outcome, relation);
                assert_eq!(receipt.a5_receipt.decision_kind, kind);
                assert!(!receipt.execution_authorized);
            }
        }
    }
    for kind in [
        B1CDriveOperatorDecisionKind::Authorize,
        B1CDriveOperatorDecisionKind::Reject,
    ] {
        for status in [
            KrvStatusAssertion::NotRevokedAtSnapshot,
            KrvStatusAssertion::RevokedAtSnapshot,
            KrvStatusAssertion::UnknownAtSnapshot,
        ] {
            let mut f = base.clone();
            f.a5 =
                upstream_fixture::fixture_for(KcvInputClass::DeterministicFixtureCandidate, kind);
            f.a5.set_a3_status(status);
            f.bind();
            let receipt = f.verify().unwrap();
            assert_eq!(receipt.a5_receipt.supplied_a3_status_assertion, status);
            assert_eq!(receipt.a5_receipt.decision_kind, kind);
            assert!(!receipt.execution_authorized);
        }
    }
}
#[test]
fn receipt_truth_effect_and_account_forgery_refuse() {
    let f = Fixture::new();
    let receipt = f.verify().unwrap();
    for field in [
        "production_authority_claimed",
        "fresh_observation_proved",
        "observation_source_identity_proved",
        "observation_source_completeness_proved",
        "observation_freshness_proved",
        "atomic_observation_proved",
        "decision_signature_binds_a6_observation",
        "expected_carrier_authority_proved",
        "live_authorization_admitted",
        "private_execution_permit_present",
        "production_broker_projection_present",
        "physical_preparation_authorized",
        "ready_for_physical_execution",
        "execution_authorized",
    ] {
        let mut changed: EocvVerificationReceipt = change_typed(&receipt, field, json!(true));
        changed.receipt_sha256 = eocv_receipt_digest(&changed).unwrap();
        assert_eq!(
            f.validate(&changed).unwrap_err().code,
            EocvFaultCode::Truth,
            "{field}"
        );
    }
    for field in [
        "a5_correspondence_receipt_verified",
        "preparation_plan_replayed",
        "proposal_plan_correspondence_verified",
        "packet_replayed",
        "descriptor_correspondence_verified",
        "observation_bundle_bytes_matched",
        "comparison_reconstructed",
    ] {
        let mut changed: EocvVerificationReceipt = change_typed(&receipt, field, json!(false));
        changed.receipt_sha256 = eocv_receipt_digest(&changed).unwrap();
        assert_eq!(
            f.validate(&changed).unwrap_err().code,
            EocvFaultCode::Truth,
            "{field}"
        );
    }
    let values = serde_json::to_value(&receipt.effect_account).unwrap();
    for (field, value) in values.as_object().unwrap() {
        let mut changed = receipt.clone();
        changed.effect_account = change_typed(
            &changed.effect_account,
            field,
            if value.is_boolean() {
                json!(true)
            } else {
                json!(1)
            },
        );
        changed.receipt_sha256 = eocv_receipt_digest(&changed).unwrap();
        assert_eq!(
            f.validate(&changed).unwrap_err().code,
            EocvFaultCode::Effect,
            "{field}"
        );
    }
}
#[test]
#[ignore = "test-owned fixture producer: explicit fresh output directory required"]
fn produce_provider_free_evidence() {
    let root = std::env::var_os("CANTOR_EOCV_EVIDENCE_OUTPUT").expect("explicit test output");
    write_evidence(Path::new(&root), &Fixture::new());
}

fn alter_scalar(value: &Value) -> Value {
    match value {
        Value::Bool(v) => json!(!v),
        Value::Number(n) => json!(n.as_u64().unwrap() + 1),
        Value::String(s) => json!(format!("{s}-tampered")),
        Value::Array(_) => json!([]),
        Value::Object(object) if object.contains_key("algorithm") => {
            json!(sha256_bytes(b"altered digest"))
        }
        _ => panic!("explicit structured mutation required"),
    }
}
#[test]
fn every_new_request_field_is_checked() {
    let base = Fixture::new();
    let object = serde_json::to_value(&base.request).unwrap();
    assert_eq!(object.as_object().unwrap().len(), 34);
    for (field, value) in object.as_object().unwrap() {
        let mut f = base.clone();
        let changed = if field == "authority_packet_request" {
            let mut packet = value.clone();
            packet["profile"] = json!("wrong-packet-profile");
            packet
        } else if field == "input_class" {
            json!("externally_supplied_candidate")
        } else {
            alter_scalar(value)
        };
        f.request = change_typed(&f.request, field, changed);
        if field != "request_sha256" {
            f.request.request_sha256 = eocv_request_digest(&f.request).unwrap();
        }
        assert!(f.verify().is_err(), "unchecked request field {field}");
    }
}
#[test]
fn every_new_receipt_field_is_checked() {
    let f = Fixture::new();
    let receipt = f.verify().unwrap();
    let object = serde_json::to_value(&receipt).unwrap();
    assert_eq!(object.as_object().unwrap().len(), 69);
    for (field, value) in object.as_object().unwrap() {
        let changed = match field.as_str() {
            "a5_receipt" => {
                let mut v = value.clone();
                v["production_authority_claimed"] = json!(true);
                v
            }
            "comparison_account" => {
                let mut v = value.clone();
                v["carrier_commit_matches"] = json!(false);
                v
            }
            "effect_account" => {
                let mut v = value.clone();
                v["process_count"] = json!(1);
                v
            }
            "input_class" => json!("externally_supplied_candidate"),
            _ => alter_scalar(value),
        };
        let mut altered: EocvVerificationReceipt = change_typed(&receipt, field, changed);
        if field != "receipt_sha256" {
            altered.receipt_sha256 = eocv_receipt_digest(&altered).unwrap();
        }
        assert!(
            f.validate(&altered).is_err(),
            "unchecked receipt field {field}"
        );
    }
}
#[test]
fn every_comparison_mismatch_and_representative_combinations_emit_receipts() {
    let base = Fixture::new();
    for mask in [
        1u16, 2, 4, 8, 16, 32, 64, 128, 256, 512, 3, 85, 341, 682, 1023,
    ] {
        let mut f = base.clone();
        if mask & 1 != 0 {
            f.bundle.observed_carrier_commit = "e".repeat(40);
        }
        if mask & 2 != 0 {
            f.bundle.observed_branch.push_str("-other");
        }
        if mask & 4 != 0 {
            f.bundle.observed_remote.push_str(".git");
        }
        if mask & 8 != 0 {
            f.bundle.observed_project.push_str("-other");
        }
        if mask & 16 != 0 {
            f.bundle.observed_unix_ms += 1;
        }
        if mask & 32 != 0 {
            f.bundle.observed_cdrive_free_bytes = 0;
        }
        if mask & 64 != 0 {
            f.bundle.build_junctions[0].kind = EocvJunctionKind::Unknown;
            f.bundle.build_junctions[0].target = None;
        }
        if mask & 128 != 0 {
            f.bundle.upstream_identities[0].artifact_sha256 = sha256_bytes(b"other");
        }
        if mask & 256 != 0 {
            f.bundle.role_observations[0].state = EocvPresenceAssertion::Present;
        }
        if mask & 512 != 0 {
            f.bundle.reserved_ref_observation.state = EocvPresenceAssertion::Unknown;
        }
        f.bind();
        let receipt = f.verify().unwrap();
        assert_eq!(receipt.status, EOCV_MISMATCHED_STATUS);
        let expected: Vec<_> = EOCV_MISMATCH_REASONS
            .into_iter()
            .enumerate()
            .filter_map(|(i, r)| (mask & (1 << i) != 0).then_some(r))
            .collect();
        assert_eq!(
            receipt.comparison_account.mismatch_reasons, expected,
            "mask {mask}"
        );
        assert!(!receipt.execution_authorized);
        assert!(!receipt.a5_receipt.live_authorization_admitted);
        f.validate(&receipt).unwrap();
    }
}
#[test]
fn supplied_capacity_time_and_class_endpoints_are_not_authority() {
    let base = Fixture::new();
    for capacity in [
        0,
        base.plan_request.minimum_cdrive_free_bytes - 1,
        base.plan_request.minimum_cdrive_free_bytes,
        u64::MAX,
    ] {
        let mut f = base.clone();
        f.bundle.observed_cdrive_free_bytes = capacity;
        f.bind();
        let receipt = f.verify().unwrap();
        assert_eq!(
            receipt.comparison_account.capacity_meets_minimum,
            capacity >= f.plan_request.minimum_cdrive_free_bytes
        );
        assert_eq!(receipt.observed_cdrive_free_bytes, capacity);
    }
    for observed in [0, u64::MAX] {
        let mut f = base.clone();
        f.a5.set_observed(observed);
        f.bundle.observed_unix_ms = observed;
        f.bind();
        assert!(
            f.verify()
                .unwrap()
                .comparison_account
                .observation_time_matches_a4
        );
    }
    let mut f = base;
    f.request.input_class = KcvInputClass::ExternallySuppliedCandidate;
    f.bundle.input_class = f.request.input_class;
    f.bind();
    let receipt = f.verify().unwrap();
    assert!(!receipt.fixture_only);
    assert!(receipt.a5_receipt.fixture_only);
    assert!(!receipt.observation_source_identity_proved);
    f.request.expected_carrier_commit = "a".repeat(40);
    f.bundle.expected_carrier_commit = f.request.expected_carrier_commit.clone();
    f.bundle.observed_carrier_commit = f.request.expected_carrier_commit.clone();
    f.bind();
    let receipt = f.verify().unwrap();
    assert!(receipt.comparison_account.carrier_commit_matches);
    assert!(!receipt.decision_signature_binds_a6_observation);
    assert!(!receipt.expected_carrier_authority_proved);
}
#[test]
fn raw_bundle_identity_precedes_parsing_and_plan_substitution_refuses() {
    let mut f = Fixture::new();
    f.raw_bundle = b"{malformed".to_vec();
    assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::RawBytes);
    f.bind_raw_bundle();
    assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::MachineForm);
    let mut f = Fixture::new();
    f.plan_request.plan_namespace_uuid = "a6000000-0000-4000-8000-000000000099".to_owned();
    f.plan_request.request_sha256 =
        b1_cdrive_production_preparation_request_digest(&f.plan_request).unwrap();
    f.plan = compile_b1_cdrive_production_preparation_plan(&f.plan_request).unwrap();
    f.raw_plan_request = to_b1_cdrive_production_preparation_request_machine_form(&f.plan_request)
        .unwrap()
        .into_bytes();
    f.raw_plan = to_b1_cdrive_production_preparation_plan_machine_form(&f.plan_request, &f.plan)
        .unwrap()
        .into_bytes();
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::Plan);
    let mut f = Fixture::new();
    f.plan_request.expected_current_commit = f.request.expected_carrier_commit.clone();
    f.plan_request.request_sha256 =
        b1_cdrive_production_preparation_request_digest(&f.plan_request).unwrap();
    f.raw_plan_request = serde_json::to_vec(&f.plan_request).unwrap();
    f.bind();
    assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::Plan);
}
#[test]
fn bundle_uuid_lineage_and_packet_boundaries_refuse() {
    let base = Fixture::new();
    for id in [
        EOCV_SOURCE_UUID,
        EOCV_SOURCE_SNAPSHOT_UUID,
        EOCV_CANONICAL_UUID,
        EOCV_SIGNATURE_UUID,
        "00000000-0000-0000-0000-000000000000",
        base.a5_receipt.decision_uuid.as_str(),
    ] {
        let mut f = base.clone();
        f.bundle.bundle_uuid = id.to_owned();
        f.request.expected_bundle_uuid = id.to_owned();
        f.bind();
        assert!(f.verify().is_err(), "colliding bundle identity {id}");
    }
    for index in [0usize, 1, 2, 3, 4, 6, 7, 8] {
        let mut f = base.clone();
        f.request.authority_packet_request.descriptors[index].content_sha256 =
            sha256_bytes(b"other");
        f.redigest_packet();
        assert!(f.verify().is_err(), "other descriptor {index}");
    }
    let mut f = base.clone();
    f.request.authority_packet_request.descriptors[5].dependency_ordinal = Some(4);
    f.redigest_packet();
    assert!(f.verify().is_err());
    let mut f = base;
    f.bundle.a5_receipt_sha256 = sha256_bytes(b"other A5");
    f.bundle.bundle_sha256 = eocv_bundle_digest(&f.bundle).unwrap();
    f.raw_bundle = serde_json::to_vec(&f.bundle).unwrap();
    f.bind_raw_bundle();
    assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::Bundle);
}
#[test]
fn full_replay_rejects_forged_upstream_receipt_after_outer_rehash() {
    let base = Fixture::new();
    let object = serde_json::to_value(&base.a5_receipt).unwrap();
    let false_fields: Vec<_> = object
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, v)| **v == json!(false))
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(false_fields.len(), 33);
    for field in false_fields {
        let mut f = base.clone();
        f.a5_receipt = change_typed(&f.a5_receipt, field, json!(true));
        f.a5_receipt.receipt_sha256 = odcv_receipt_digest(&f.a5_receipt).unwrap();
        f.request.a5_receipt_sha256 = f.a5_receipt.receipt_sha256.clone();
        f.bundle.a5_receipt_sha256 = f.a5_receipt.receipt_sha256.clone();
        f.bundle.bundle_sha256 = eocv_bundle_digest(&f.bundle).unwrap();
        f.raw_bundle = serde_json::to_vec(&f.bundle).unwrap();
        f.bind_raw_bundle();
        assert_eq!(
            f.verify().unwrap_err().code,
            EocvFaultCode::Predecessor,
            "{field}"
        );
    }
}
#[test]
fn canonical_bundle_request_receipt_framing_and_nested_shapes_refuse() {
    let f = Fixture::new();
    let bundle = to_eocv_bundle_machine_form(&f.bundle).unwrap();
    let request = to_eocv_request_machine_form(&f.request).unwrap();
    let receipt = serde_json::to_string(&f.verify().unwrap()).unwrap();
    for (kind, text) in [
        ("bundle", &bundle),
        ("request", &request),
        ("receipt", &receipt),
    ] {
        for altered in [
            format!(" {text}"),
            format!("{text} "),
            format!("\u{feff}{text}"),
            format!("{text}\r\n"),
            format!("{text}{{}}"),
            text.replacen("{", "{\"unknown\":true,", 1),
            text.replacen("{", "{\"profile\":\"duplicate\",", 1),
            text.replacen("profile", "pro\\u0066ile", 1),
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(text).unwrap()).unwrap(),
            serde_json::to_string(&serde_json::from_str::<Value>(text).unwrap()).unwrap(),
        ] {
            let refused = match kind {
                "bundle" => from_eocv_bundle_machine_form(&altered).is_err(),
                "request" => from_eocv_request_machine_form(&altered).is_err(),
                _ => from_eocv_receipt_machine_form(
                    &f.request,
                    &f.predecessor(),
                    &f.raw_plan_request,
                    &f.raw_plan,
                    &f.raw_bundle,
                    &altered,
                )
                .is_err(),
            };
            assert!(refused, "noncanonical {kind}");
        }
    }
    let mut f = f;
    f.bundle.build_junctions[0].kind = EocvJunctionKind::Missing;
    f.bundle.build_junctions[0].target = None;
    f.bind();
    let text = String::from_utf8(f.raw_bundle.clone()).unwrap();
    let altered = text.replacen(",\"target\":null", "", 1);
    assert!(from_eocv_bundle_machine_form(&altered).is_err());
    for altered in [
        text.replacen("\"kind\":\"missing\"", "\"kind\":{\"missing\":null}", 1),
        text.replacen("\"state\":\"absent\"", "\"state\":{\"absent\":null}", 1),
        text.replacen("\"kind\":\"missing\"", "\"kind\":\"nonexistent\"", 1),
    ] {
        assert!(from_eocv_bundle_machine_form(&altered).is_err());
    }
}
#[test]
fn malformed_observation_coordinates_refuse_after_full_rebinding() {
    let base = Fixture::new();
    for case in 0..10 {
        let mut f = base.clone();
        match case {
            0 => {
                f.bundle.build_junctions.pop();
            }
            1 => f.bundle.build_junctions.swap(0, 1),
            2 => f.bundle.build_junctions[0].target = None,
            3 => {
                f.bundle.build_junctions[0].kind = EocvJunctionKind::Missing;
            }
            4 => {
                f.bundle.upstream_identities.pop();
            }
            5 => f.bundle.upstream_identities.swap(0, 1),
            6 => {
                f.bundle.role_observations.pop();
            }
            7 => f.bundle.role_observations.swap(0, 1),
            8 => f.bundle.role_observations[0].path.push_str("-wrong"),
            _ => f
                .bundle
                .reserved_ref_observation
                .reference
                .push_str("-wrong"),
        }
        f.bind();
        assert!(f.verify().is_err(), "coordinate {case}");
    }
}
#[test]
fn bounded_forms_references_and_opaque_targets() {
    let base = Fixture::new();
    for count in [0, 49] {
        let mut f = base.clone();
        f.request.evidence_references = (0..count).map(|n| format!("r{n}")).collect();
        f.request.request_sha256 = eocv_request_digest(&f.request).unwrap();
        assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::Evidence);
    }
    for refs in [
        vec!["duplicate".to_owned(); 2],
        vec!["".to_owned()],
        vec![" ".to_owned()],
    ] {
        let mut f = base.clone();
        f.bundle.evidence_references = refs;
        f.bind();
        assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::Evidence);
    }
    let mut f = base;
    f.request.evidence_references = (0..48)
        .map(|n| format!("https://never-resolve.invalid/{n}"))
        .collect();
    f.bundle.evidence_references = (0..48)
        .map(|n| format!("D:/not-a-real-declared-target/{n}"))
        .collect();
    f.bundle.observed_project = "x".repeat(8192);
    f.bind();
    assert_eq!(
        f.verify().unwrap().effect_account,
        TwvEffectAccount::default()
    );
    f.bundle.observed_project.push('x');
    assert!(eocv_bundle_digest(&f.bundle).is_err());
    let mut deep = json!(0);
    for _ in 0..33 {
        deep = json!({"x":deep});
    }
    assert!(from_eocv_bundle_machine_form(&deep.to_string()).is_err());
    let wide: serde_json::Map<String, Value> =
        (0..4097).map(|i| (format!("f{i}"), json!(i))).collect();
    assert!(from_eocv_request_machine_form(&Value::Object(wide).to_string()).is_err());
    assert!(from_eocv_request_machine_form(&" ".repeat(EOCV_MAX_FORM_BYTES + 1)).is_err());
}

#[test]
fn every_retained_payload_tamper_refuses_even_after_manifest_rehash() {
    let f = Fixture::new();
    let root = temporary("all-payloads");
    write_evidence(&root, &f);
    for name in &EOCV_EVIDENCE_FILES[..25] {
        let original = fs::read(root.join(name)).unwrap();
        let text = std::str::from_utf8(&original)
            .unwrap()
            .replacen("{", "{\"unknown\":0,", 1);
        fs::write(root.join(name), text).unwrap();
        rehash_evidence(&root);
        assert!(verify_eocv_evidence_directory(&root).is_err(), "{name}");
        fs::write(root.join(name), original).unwrap();
        rehash_evidence(&root);
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn manifest_fields_and_ordered_artifact_coordinates_are_checked() {
    let f = Fixture::new();
    let root = temporary("manifest");
    write_evidence(&root, &f);
    let original = fs::read(root.join("evidence_manifest.json")).unwrap();
    let baseline: EocvEvidenceManifest = serde_json::from_slice(&original).unwrap();
    let fields = serde_json::to_value(&baseline).unwrap();
    assert_eq!(fields.as_object().unwrap().len(), 16);
    for (field, value) in fields.as_object().unwrap() {
        let changed = if field == "manifest_uuid" {
            json!("00000000-0000-0000-0000-000000000000")
        } else {
            alter_scalar(value)
        };
        let mut m: EocvEvidenceManifest = change_typed(&baseline, field, changed);
        if field != "manifest_sha256" {
            m.manifest_sha256 = eocv_evidence_manifest_digest(&m).unwrap();
        }
        fs::write(root.join("evidence_manifest.json"), line(&m)).unwrap();
        assert!(
            verify_eocv_evidence_directory(&root).is_err(),
            "manifest {field}"
        );
    }
    for mode in 0..9 {
        let mut m = baseline.clone();
        match mode {
            0 => m.artifacts.swap(0, 1),
            1 => m.artifacts[0].path = "../outside".to_owned(),
            2 => m.artifacts[0].path = "C:/outside".to_owned(),
            3 => m.artifacts[0].path = m.artifacts[1].path.clone(),
            4 => m.artifacts.push(m.artifacts[0].clone()),
            5 => m.artifacts[0].bytes = u64::MAX,
            6 => m.artifacts[0].sha256 = sha256_bytes(b"wrong artifact bytes"),
            7 => m.total_artifact_bytes = u64::MAX,
            _ => m.artifacts[0].path = "subfolder/../predecessor_request.json".to_owned(),
        }
        m.manifest_sha256 = eocv_evidence_manifest_digest(&m).unwrap();
        fs::write(root.join("evidence_manifest.json"), line(&m)).unwrap();
        assert!(
            verify_eocv_evidence_directory(&root).is_err(),
            "artifact coordinate {mode}"
        );
    }
    fs::write(root.join("evidence_manifest.json"), original).unwrap();
    verify_eocv_evidence_directory(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn evidence_membership_framing_and_rehashed_receipt_promotion_refuse() {
    let f = Fixture::new();
    for mode in 0..8 {
        let root = temporary("membership");
        write_evidence(&root, &f);
        match mode {
            0 => fs::remove_file(root.join("observation_bundle.json")).unwrap(),
            1 => fs::write(root.join("extra.json"), b"{}\n").unwrap(),
            2 => {
                fs::remove_file(root.join("receipt.json")).unwrap();
                fs::create_dir(root.join("receipt.json")).unwrap();
            }
            3 => {
                let mut receipt = f.verify().unwrap();
                receipt.execution_authorized = true;
                receipt.receipt_sha256 = eocv_receipt_digest(&receipt).unwrap();
                fs::write(root.join("receipt.json"), line(&receipt)).unwrap();
                rehash_evidence(&root);
            }
            4 => fs::write(root.join("receipt.json"), b"").unwrap(),
            _ => {
                let name = "observation_bundle.json";
                let mut bytes = fs::read(root.join(name)).unwrap();
                match mode {
                    5 => {
                        bytes.pop();
                    }
                    6 => bytes.push(b'\n'),
                    _ => bytes.insert(bytes.len() - 1, b'\r'),
                }
                fs::write(root.join(name), bytes).unwrap();
                rehash_evidence(&root);
            }
        }
        let output = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "mode {mode}");
        assert!(output.stdout.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn cli_argument_relative_path_and_file_total_bounds() {
    for args in [vec![], vec!["x"; 23], vec!["x"; 25], vec!["x"; 26]] {
        let out = Command::new(CLI).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    for args in [vec![], vec!["x", "y"]] {
        let out = Command::new(EVIDENCE_CLI).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    let f = Fixture::new();
    let root = temporary("relative");
    write_evidence(&root, &f);
    let output = Command::new(CLI)
        .current_dir(&root)
        .args(&EOCV_EVIDENCE_FILES[..24])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(output.stdout, line(&f.verify().unwrap()));
    let paths: Vec<_> = EOCV_EVIDENCE_FILES[..24]
        .iter()
        .map(|n| root.join(n))
        .collect();
    let mut duplicate = paths.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(verify_eocv_payload_paths(&duplicate).is_err());
    fs::write(
        root.join("observation_bundle.json"),
        vec![b'x'; EOCV_MAX_FORM_BYTES + 2],
    )
    .unwrap();
    assert_eq!(
        verify_eocv_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Size
    );
    assert_eq!(
        verify_eocv_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::Size
    );
    let bytes = vec![b'x'; EOCV_MAX_FORM_BYTES];
    for name in EOCV_EVIDENCE_FILES {
        fs::write(root.join(name), &bytes).unwrap();
    }
    assert_eq!(
        verify_eocv_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::Size
    );
    fs::remove_dir_all(root).unwrap();
}
#[cfg(windows)]
#[test]
fn windows_junction_directory_and_ancestor_refuse_without_target_changes() {
    let f = Fixture::new();
    let root = temporary("junction");
    write_evidence(&root, &f);
    let junction = root.join("linked");
    assert!(
        !root
            .to_string_lossy()
            .chars()
            .any(|c| "&|<>^%!\"\r\n".contains(c))
    );
    let result = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        verify_eocv_evidence_directory(&junction).unwrap_err().code,
        EocvFaultCode::Path
    );
    let paths: Vec<_> = EOCV_EVIDENCE_FILES[..24]
        .iter()
        .map(|n| junction.join(n))
        .collect();
    assert_eq!(
        verify_eocv_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Path
    );
    fs::remove_dir(&junction).expect("unlink only the test-owned junction");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 26);
    verify_eocv_evidence_directory(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn direct_symlink_inputs_refuse() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let root = temporary("symlink");
    write_evidence(&root, &f);
    let target = root.join("observation_bundle.json");
    let link = root.join("bundle-link.json");
    symlink(&target, &link).unwrap();
    let mut paths: Vec<_> = EOCV_EVIDENCE_FILES[..24]
        .iter()
        .map(|n| root.join(n))
        .collect();
    paths[22] = link;
    assert_eq!(
        verify_eocv_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Path
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn self_digest_domains_and_canonical_byte_order_are_explicit() {
    let f = Fixture::new();
    let mut request = f.request.clone();
    request.request_sha256 = empty();
    let mut bytes = b"cantor.b1.expected-observation.request.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&request).unwrap());
    assert_eq!(
        eocv_request_digest(&f.request).unwrap(),
        sha256_bytes(&bytes)
    );
    let mut bundle = f.bundle.clone();
    bundle.bundle_sha256 = empty();
    let mut bytes = b"cantor.b1.expected-observation.bundle.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&bundle).unwrap());
    assert_eq!(eocv_bundle_digest(&f.bundle).unwrap(), sha256_bytes(&bytes));
    let receipt = f.verify().unwrap();
    let mut normalized = receipt.clone();
    normalized.receipt_sha256 = empty();
    let mut bytes = b"cantor.b1.expected-observation.receipt.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&normalized).unwrap());
    assert_eq!(eocv_receipt_digest(&receipt).unwrap(), sha256_bytes(&bytes));
    let root = temporary("domains");
    write_evidence(&root, &f);
    let m: EocvEvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap();
    let mut normalized = m.clone();
    normalized.manifest_sha256 = empty();
    let mut bytes = b"cantor.b1.expected-observation.evidence-manifest.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&normalized).unwrap());
    assert_eq!(
        eocv_evidence_manifest_digest(&m).unwrap(),
        sha256_bytes(&bytes)
    );
    let form = to_eocv_evidence_manifest_machine_form(&m).unwrap();
    assert_eq!(
        raw_line(form.as_bytes()),
        fs::read(root.join("evidence_manifest.json")).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn production_has_no_effect_or_producer_capability() {
    let core = include_str!("../src/b1_expected_observation_correspondence.rs");
    let evidence = include_str!("../src/b1_expected_observation_correspondence_evidence.rs");
    for forbidden in [
        "unsafe {",
        "SigningKey",
        "std::process",
        "std::env",
        "SystemTime::now",
        "TcpStream",
        ".write(true)",
        ".create(true)",
        "fs::write",
        "remove_file(",
        "remove_dir(",
        "produce_provider_free_evidence",
        "support/eocv_predecessor_fixture",
    ] {
        assert!(!core.contains(forbidden), "core {forbidden}");
        assert!(!evidence.contains(forbidden), "evidence {forbidden}");
    }
    assert!(core.contains("crate::verify_odcv_operator_decision("));
    assert!(core.contains("crate::compile_b1_cdrive_production_preparation_plan("));
    assert!(core.contains(
        "crate::from_b1_cdrive_production_preparation_commission_proposal_machine_form("
    ));
    assert!(core.contains("proposal.inherited_plan_sha256 != plan.plan_sha256"));
}

#[test]
fn raw_resource_limits_precede_expensive_predecessor_replay() {
    let base = Fixture::new();
    for slot in 0..3 {
        let mut f = base.clone();
        // A broken predecessor would refuse as Predecessor if it were reached.
        f.a5.raw_envelope = b"invalid A5 envelope".to_vec();
        let excessive = vec![b'x'; EOCV_MAX_FORM_BYTES + 1];
        match slot {
            0 => f.raw_plan_request = excessive,
            1 => f.raw_plan = excessive,
            _ => f.raw_bundle = excessive,
        }
        assert_eq!(f.verify().unwrap_err().code, EocvFaultCode::Size);
    }
}
