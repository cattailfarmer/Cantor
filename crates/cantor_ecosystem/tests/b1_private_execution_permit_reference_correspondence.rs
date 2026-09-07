//! Full A7 replay over the governed A6 test fixture; no private permit material.
#[allow(dead_code)]
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

const CLI: &str = env!("CARGO_BIN_EXE_cantor-b1-private-execution-permit-reference-verify");
const EVIDENCE_CLI: &str =
    env!("CARGO_BIN_EXE_cantor-b1-private-execution-permit-reference-evidence-verify");
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn empty() -> ContentDigest {
    sha256_bytes(b"")
}

fn temporary(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cantor-perc-{label}-{}-{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn line<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn change_typed<T: Serialize + DeserializeOwned>(original: &T, field: &str, value: Value) -> T {
    let mut object = serde_json::to_value(original).unwrap();
    object[field] = value;
    serde_json::from_value(object).unwrap()
}

fn alter_scalar(value: &Value) -> Value {
    match value {
        Value::Bool(inner) => json!(!inner),
        Value::Number(number) => json!(number.as_u64().unwrap() + 1),
        Value::String(text) => json!(format!("{text}-tampered")),
        Value::Array(_) => json!([]),
        Value::Object(object) if object.contains_key("algorithm") => {
            json!(sha256_bytes(b"changed digest"))
        }
        _ => panic!("explicit structured mutation required"),
    }
}

fn explicit_paths(root: &Path) -> Vec<PathBuf> {
    [&PERC_EVIDENCE_FILES[..25], &PERC_EVIDENCE_FILES[26..28]]
        .concat()
        .iter()
        .map(|name| root.join(name))
        .collect()
}

fn rotate_first_field(text: &str) -> String {
    let inner = &text[1..text.len() - 1];
    let comma = inner.find(',').expect("top-level first field separator");
    format!("{{{},{}}}", &inner[comma + 1..], &inner[..comma])
}

#[derive(Clone)]
struct A6Fixture {
    a5: upstream_fixture::Fixture,
    a5_receipt: OdcvVerificationReceipt,
    raw_plan_request: Vec<u8>,
    plan_request: B1CDriveProductionPreparationPlanRequest,
    raw_plan: Vec<u8>,
    plan: B1CDriveProductionPreparationPlan,
    bundle: EocvObservationBundle,
    raw_bundle: Vec<u8>,
    request: EocvVerificationRequest,
}

impl A6Fixture {
    fn new() -> Self {
        let a5 = upstream_fixture::fixture_for(
            KcvInputClass::DeterministicFixtureCandidate,
            B1CDriveOperatorDecisionKind::Authorize,
        );
        let a5_receipt = a5.verify().unwrap();
        let raw_plan_request = include_str!(
            "../../../experiments/self_work_update_broker_b1_cdrive_production_preparation_plan_p0/implementation_provider_free_evidence/request.json"
        )
        .trim_end_matches('\n')
        .as_bytes()
        .to_vec();
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
                .map(|junction| EocvJunctionObservation {
                    source: junction.source.clone(),
                    kind: EocvJunctionKind::Junction,
                    target: Some(junction.target.clone()),
                })
                .collect(),
            upstream_identities: plan_request.upstream_identities.clone(),
            role_observations: plan
                .roles
                .iter()
                .map(|role| EocvRoleObservation {
                    kind: role.kind,
                    path: role.path.clone(),
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
            authority_packet_request: a5.request.authority_packet_request.clone(),
            authority_packet_request_sha256: empty(),
            authority_packet_sha256: empty(),
            a6_candidate_uuid: a5.request.authority_packet_request.descriptors[5]
                .candidate_uuid
                .clone(),
            a6_descriptor_sha256: empty(),
            observation_bundle_bytes: 1,
            observation_bundle_raw_sha256: empty(),
            expected_bundle_uuid: bundle.bundle_uuid.clone(),
            expected_carrier_commit: bundle.expected_carrier_commit.clone(),
            input_class: bundle.input_class,
            evidence_references: vec!["opaque:A6-request".to_owned()],
            maximum_attempts: 1,
            automatic_retry_count: 0,
            automatic_cleanup_count: 0,
            request_sha256: empty(),
        };
        let mut fixture = Self {
            a5,
            a5_receipt,
            raw_plan_request,
            plan_request,
            raw_plan,
            plan,
            bundle,
            raw_bundle: Vec::new(),
            request,
        };
        fixture.bind();
        fixture
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

    fn redigest_packet(&mut self) {
        for descriptor in &mut self.request.authority_packet_request.descriptors {
            descriptor.descriptor_sha256 = b1oapr_descriptor_digest(descriptor).unwrap();
        }
        self.request.a6_descriptor_sha256 = self.request.authority_packet_request.descriptors[5]
            .descriptor_sha256
            .clone();
        self.request.authority_packet_request.request_sha256 =
            b1oapr_request_digest(&self.request.authority_packet_request).unwrap();
        self.request.authority_packet_request_sha256 =
            self.request.authority_packet_request.request_sha256.clone();
        self.request.authority_packet_sha256 =
            compile_b1oapr_packet(&self.request.authority_packet_request)
                .unwrap()
                .packet_sha256;
        self.request.request_sha256 = eocv_request_digest(&self.request).unwrap();
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
        let descriptor = &mut self.request.authority_packet_request.descriptors[5];
        descriptor.declared_bytes = self.raw_bundle.len() as u64;
        descriptor.content_sha256 = sha256_bytes(&self.raw_bundle);
        self.request.observation_bundle_bytes = descriptor.declared_bytes;
        self.request.observation_bundle_raw_sha256 = descriptor.content_sha256.clone();
        self.redigest_packet();
    }
}

#[derive(Clone)]
struct Fixture {
    a6: A6Fixture,
    a6_receipt: EocvVerificationReceipt,
    envelope: PercReferenceEnvelope,
    raw_envelope: Vec<u8>,
    request: PercVerificationRequest,
}

impl Fixture {
    fn new() -> Self {
        let a6 = A6Fixture::new();
        let a6_receipt = a6.verify().unwrap();
        let descriptor = a6.request.authority_packet_request.descriptors[6].clone();
        let envelope = PercReferenceEnvelope {
            profile: PERC_ENVELOPE_PROFILE.to_owned(),
            envelope_uuid: "a7000000-0000-4000-8000-000000000001".to_owned(),
            a6_receipt_sha256: a6_receipt.receipt_sha256.clone(),
            candidate_uuid: descriptor.candidate_uuid.clone(),
            authority_name: descriptor.authority_name.clone(),
            artifact_kind: descriptor.artifact_kind.clone(),
            opaque_reference: descriptor.opaque_reference.clone(),
            content_sha256: descriptor.content_sha256.clone(),
            declared_bytes: descriptor.declared_bytes,
            confidentiality: descriptor.confidentiality,
            required_verifier_profile: descriptor.required_verifier_profile.clone(),
            fixture_only: descriptor.fixture_only,
            dependency_ordinal: descriptor.dependency_ordinal.unwrap(),
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            evidence_references: vec!["a7_fixture_evidence".to_owned()],
            envelope_sha256: empty(),
        };
        let request = PercVerificationRequest {
            profile: PERC_REQUEST_PROFILE.to_owned(),
            source_snapshot_uuid: PERC_SOURCE_SNAPSHOT_UUID.to_owned(),
            canonical_uuid: PERC_CANONICAL_UUID.to_owned(),
            signature_uuid: PERC_SIGNATURE_UUID.to_owned(),
            source_custody_commit: PERC_SOURCE_CUSTODY_COMMIT.to_owned(),
            source_bookend_commit: PERC_SOURCE_BOOKEND_COMMIT.to_owned(),
            a6_implementation_commit: PERC_A6_IMPLEMENTATION_COMMIT.to_owned(),
            a6_bookend_commit: PERC_A6_BOOKEND_COMMIT.to_owned(),
            a6_proof_uuid: PERC_A6_PROOF_UUID.to_owned(),
            a6_verification_request_sha256: a6.request.request_sha256.clone(),
            expected_a6_receipt_sha256: a6_receipt.receipt_sha256.clone(),
            authority_packet_request_sha256: empty(),
            expected_authority_packet_sha256: empty(),
            expected_candidate_uuid: descriptor.candidate_uuid,
            expected_descriptor_sha256: descriptor.descriptor_sha256,
            expected_envelope_uuid: envelope.envelope_uuid.clone(),
            expected_envelope_bytes: 1,
            expected_envelope_raw_sha256: empty(),
            expected_envelope_sha256: empty(),
            expected_authority_name: descriptor.authority_name,
            expected_artifact_kind: descriptor.artifact_kind,
            expected_opaque_reference: descriptor.opaque_reference,
            expected_content_sha256: descriptor.content_sha256,
            expected_declared_bytes: descriptor.declared_bytes,
            expected_confidentiality: descriptor.confidentiality,
            expected_verifier_profile: descriptor.required_verifier_profile,
            expected_fixture_only: descriptor.fixture_only,
            expected_dependency_ordinal: descriptor.dependency_ordinal.unwrap(),
            input_class: KcvInputClass::DeterministicFixtureCandidate,
            evidence_references: envelope.evidence_references.clone(),
            maximum_attempts: 1,
            automatic_retry_count: 0,
            automatic_cleanup_count: 0,
            request_sha256: empty(),
        };
        let mut fixture = Self {
            a6,
            a6_receipt,
            envelope,
            raw_envelope: Vec::new(),
            request,
        };
        fixture.bind_all();
        fixture
    }

    fn predecessor(&self) -> PercPredecessor<'_> {
        PercPredecessor {
            a6_request: &self.a6.request,
            a6_predecessor: self.a6.predecessor(),
            raw_plan_request: &self.a6.raw_plan_request,
            raw_plan: &self.a6.raw_plan,
            raw_observation_bundle: &self.a6.raw_bundle,
            a6_receipt: &self.a6_receipt,
        }
    }

    fn verify(&self) -> Result<PercVerificationReceipt, EocvFault> {
        verify_perc_reference_correspondence(&self.request, &self.predecessor(), &self.raw_envelope)
    }

    fn bind_packet(&mut self) {
        let fixture = self.request.input_class == KcvInputClass::DeterministicFixtureCandidate;
        let mut descriptor = B1OaprCandidateDescriptor {
            ordinal: 7,
            candidate_uuid: self.request.expected_candidate_uuid.clone(),
            authority_name: self.request.expected_authority_name.clone(),
            artifact_kind: self.request.expected_artifact_kind.clone(),
            origin: if fixture {
                B1OaprCandidateOrigin::DeterministicFixtureCandidate
            } else {
                B1OaprCandidateOrigin::ExternallySuppliedCandidate
            },
            opaque_reference: self.request.expected_opaque_reference.clone(),
            content_sha256: self.request.expected_content_sha256.clone(),
            declared_bytes: self.request.expected_declared_bytes,
            confidentiality: self.request.expected_confidentiality,
            required_verifier_profile: self.request.expected_verifier_profile.clone(),
            fixture_only: self.request.expected_fixture_only,
            dependency_ordinal: Some(self.request.expected_dependency_ordinal),
            descriptor_sha256: empty(),
        };
        descriptor.descriptor_sha256 = b1oapr_descriptor_digest(&descriptor).unwrap();
        self.request.expected_descriptor_sha256 = descriptor.descriptor_sha256.clone();
        let mut current = self.a6.request.authority_packet_request.clone();
        current.descriptors[6] = descriptor;
        current.request_sha256 = b1oapr_request_digest(&current).unwrap();
        self.request.authority_packet_request_sha256 = current.request_sha256.clone();
        self.request.expected_authority_packet_sha256 =
            compile_b1oapr_packet(&current).unwrap().packet_sha256;
    }

    fn bind_envelope_raw(&mut self) {
        self.envelope.envelope_sha256 = perc_envelope_digest(&self.envelope).unwrap();
        self.raw_envelope = serde_json::to_vec(&self.envelope).unwrap();
        self.request.expected_envelope_bytes = self.raw_envelope.len() as u64;
        self.request.expected_envelope_raw_sha256 = sha256_bytes(&self.raw_envelope);
        self.request.expected_envelope_sha256 = self.envelope.envelope_sha256.clone();
        self.request.request_sha256 = perc_request_digest(&self.request).unwrap();
    }

    fn bind_all(&mut self) {
        self.a6_receipt = self.a6.verify().unwrap();
        self.request.a6_verification_request_sha256 = self.a6.request.request_sha256.clone();
        self.request.expected_a6_receipt_sha256 = self.a6_receipt.receipt_sha256.clone();
        self.envelope.a6_receipt_sha256 = self.a6_receipt.receipt_sha256.clone();
        self.bind_packet();
        self.bind_envelope_raw();
    }
}

fn write_evidence(root: &Path, fixture: &Fixture) {
    fs::create_dir(root).expect("fresh caller-owned evidence root");
    let a6_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../experiments/b1_expected_observation_correspondence_p0/implementation_provider_free_evidence");
    for name in EOCV_EVIDENCE_FILES {
        let destination = match name {
            "verification_request.json" => "a6_verification_request.json",
            "receipt.json" => "a6_receipt.json",
            "evidence_manifest.json" => "a6_evidence_manifest.json",
            other => other,
        };
        fs::copy(a6_root.join(name), root.join(destination)).unwrap();
    }
    let retained_a6_request: EocvVerificationRequest = serde_json::from_slice(
        fs::read(root.join("a6_verification_request.json"))
            .unwrap()
            .strip_suffix(b"\n")
            .unwrap(),
    )
    .unwrap();
    let retained_a6_receipt: EocvVerificationReceipt = serde_json::from_slice(
        fs::read(root.join("a6_receipt.json"))
            .unwrap()
            .strip_suffix(b"\n")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(retained_a6_request, fixture.a6.request);
    assert_eq!(retained_a6_receipt, fixture.a6_receipt);

    let receipt = fixture.verify().unwrap();
    fs::write(
        root.join("permit_reference_envelope.json"),
        line(&fixture.envelope),
    )
    .unwrap();
    fs::write(
        root.join("verification_request.json"),
        line(&fixture.request),
    )
    .unwrap();
    fs::write(root.join("receipt.json"), line(&receipt)).unwrap();
    let artifacts: Vec<PercEvidenceArtifact> = PERC_EVIDENCE_FILES[..29]
        .iter()
        .map(|name| {
            let bytes = fs::read(root.join(name)).unwrap();
            PercEvidenceArtifact {
                path: (*name).to_owned(),
                bytes: bytes.len() as u64,
                sha256: sha256_bytes(&bytes),
            }
        })
        .collect();
    let mut manifest = PercEvidenceManifest {
        profile: PERC_EVIDENCE_PROFILE.to_owned(),
        manifest_uuid: "a7000000-0000-4000-8000-000000000002".to_owned(),
        source_snapshot_uuid: PERC_SOURCE_SNAPSHOT_UUID.to_owned(),
        canonical_uuid: PERC_CANONICAL_UUID.to_owned(),
        total_artifact_bytes: artifacts.iter().map(|artifact| artifact.bytes).sum(),
        artifacts,
        artifact_count: 29,
        retained_authority_packet_sha256: receipt.authority_packet_sha256.clone(),
        retained_a6_receipt_sha256: receipt.a6_receipt_sha256.clone(),
        retained_reference_envelope_sha256: receipt.reference_envelope_sha256.clone(),
        retained_receipt_sha256: receipt.receipt_sha256.clone(),
        deterministic_replay_count: 2,
        required_fresh_process_replay_count: 2,
        byte_identical: true,
        effect_count: 0,
        manifest_sha256: empty(),
    };
    manifest.manifest_sha256 = perc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}

fn rehash_evidence(root: &Path) {
    let mut manifest: PercEvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap();
    for artifact in &mut manifest.artifacts {
        let bytes = fs::read(root.join(&artifact.path)).unwrap();
        artifact.bytes = bytes.len() as u64;
        artifact.sha256 = sha256_bytes(&bytes);
    }
    manifest.total_artifact_bytes = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.bytes)
        .sum();
    manifest.manifest_sha256 = perc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
}

#[test]
fn full_a6_replay_yields_non_authorizing_matched_receipt() {
    let fixture = Fixture::new();
    let receipt = fixture.verify().unwrap();
    assert_eq!(receipt.status, PERC_MATCHED_STATUS);
    assert_eq!(receipt.authority, PERC_AUTHORITY);
    assert!(receipt.correspondence_account.all_correspondence_matches);
    assert!(receipt.private_execution_permit_reference_correspondence_proved);
    assert!(!receipt.private_execution_permit_present);
    assert!(!receipt.execution_authorized);
    assert_eq!(receipt.effect_account, TwvEffectAccount::default());
    validate_perc_receipt(
        &fixture.request,
        &fixture.predecessor(),
        &fixture.raw_envelope,
        &receipt,
    )
    .unwrap();
}

#[test]
fn all_machine_forms_round_trip_only_under_the_full_retained_chain() {
    let fixture = Fixture::new();
    let envelope_text = to_perc_envelope_machine_form(&fixture.envelope).unwrap();
    assert_eq!(
        from_perc_envelope_machine_form(&envelope_text).unwrap(),
        fixture.envelope
    );
    let request_text = to_perc_request_machine_form(&fixture.request).unwrap();
    assert_eq!(
        from_perc_request_machine_form(&request_text).unwrap(),
        fixture.request
    );
    let receipt = fixture.verify().unwrap();
    let receipt_text = to_perc_receipt_machine_form(
        &fixture.request,
        &fixture.predecessor(),
        &fixture.raw_envelope,
        &receipt,
    )
    .unwrap();
    assert_eq!(
        from_perc_receipt_machine_form(
            &fixture.request,
            &fixture.predecessor(),
            &fixture.raw_envelope,
            &receipt_text,
        )
        .unwrap(),
        receipt
    );
}

#[test]
fn externally_supplied_public_reference_is_comparable_without_becoming_authority() {
    let mut fixture = Fixture::new();
    fixture.request.input_class = KcvInputClass::ExternallySuppliedCandidate;
    fixture.request.expected_fixture_only = false;
    fixture.envelope.input_class = KcvInputClass::ExternallySuppliedCandidate;
    fixture.envelope.fixture_only = false;
    fixture.bind_all();
    let receipt = fixture.verify().unwrap();
    assert_eq!(receipt.status, PERC_MATCHED_STATUS);
    assert!(receipt.private_execution_permit_reference_correspondence_proved);
    assert!(!receipt.private_execution_permit_present);
    assert!(!receipt.execution_authorized);
    assert_eq!(receipt.effect_account, TwvEffectAccount::default());
}

#[test]
fn well_formed_adverse_reference_is_descriptive_not_malformed() {
    let mut fixture = Fixture::new();
    fixture.envelope.opaque_reference = "different_fixture_reference".to_owned();
    fixture.bind_envelope_raw();
    let receipt = fixture.verify().unwrap();
    assert_eq!(receipt.status, PERC_MISMATCHED_STATUS);
    assert_eq!(
        receipt.correspondence_account.mismatch_reasons,
        vec![PercMismatchReason::OpaqueReferenceMismatch]
    );
    assert!(!receipt.private_execution_permit_reference_correspondence_proved);
    assert!(!receipt.private_execution_permit_present);
}

#[test]
fn raw_envelope_tamper_refuses_before_parse_without_echo() {
    let mut fixture = Fixture::new();
    fixture.raw_envelope.push(b' ');
    let error = fixture.verify().expect_err("raw byte substitution");
    assert_eq!(error.code, EocvFaultCode::RawBytes);
    assert!(!error.message.contains(&fixture.envelope.opaque_reference));
}

#[test]
fn unsafe_reference_refuses_without_echo() {
    let mut fixture = Fixture::new();
    fixture.envelope.opaque_reference = "private/material/must-not-echo".to_owned();
    fixture.bind_envelope_raw();
    let error = fixture.verify().expect_err("unsafe reference shape");
    assert_eq!(error.code, EocvFaultCode::Shape);
    assert!(!error.message.contains(&fixture.envelope.opaque_reference));
}

#[test]
fn retained_receipt_substitution_refuses_machine_form_restart() {
    let fixture = Fixture::new();
    let mut receipt = fixture.verify().unwrap();
    receipt.execution_authorized = true;
    let substituted = serde_json::to_string(&receipt).unwrap();
    let error = from_perc_receipt_machine_form(
        &fixture.request,
        &fixture.predecessor(),
        &fixture.raw_envelope,
        &substituted,
    )
    .expect_err("substituted retained receipt");
    assert_eq!(error.code, EocvFaultCode::Restart);
}

#[test]
fn independent_evidence_and_both_bounded_clis_replay_exact_receipt() {
    let fixture = Fixture::new();
    let root = temporary("replay");
    write_evidence(&root, &fixture);
    let replay = verify_perc_evidence_directory(&root).unwrap();
    assert_eq!(replay.receipt, fixture.verify().unwrap());
    assert_eq!(replay.manifest.artifact_count, 29);
    assert_eq!(replay.deterministic_replay_count, 2);
    assert!(replay.byte_identical);

    let directory_output = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
    assert!(
        directory_output.status.success(),
        "{:?}",
        directory_output.stderr
    );
    assert!(directory_output.stderr.is_empty());
    assert_eq!(directory_output.stdout, line(&replay.receipt));

    let paths = explicit_paths(&root);
    assert_eq!(
        verify_perc_payload_paths(&paths).unwrap(),
        replay.receipt_machine_form
    );
    let explicit_output = Command::new(CLI).args(&paths).output().unwrap();
    assert!(
        explicit_output.status.success(),
        "{:?}",
        explicit_output.stderr
    );
    assert!(explicit_output.stderr.is_empty());
    assert_eq!(explicit_output.stdout, line(&replay.receipt));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn evidence_membership_and_rehashed_retained_identity_refuse() {
    let fixture = Fixture::new();
    let extra_root = temporary("extra");
    write_evidence(&extra_root, &fixture);
    fs::write(extra_root.join("extra.json"), b"{}\n").unwrap();
    assert_eq!(
        verify_perc_evidence_directory(&extra_root)
            .unwrap_err()
            .code,
        EocvFaultCode::Evidence
    );
    fs::remove_dir_all(extra_root).unwrap();

    let missing_root = temporary("missing");
    write_evidence(&missing_root, &fixture);
    fs::remove_file(missing_root.join("permit_reference_envelope.json")).unwrap();
    assert_eq!(
        verify_perc_evidence_directory(&missing_root)
            .unwrap_err()
            .code,
        EocvFaultCode::Evidence
    );
    fs::remove_dir_all(missing_root).unwrap();

    let restart_root = temporary("restart");
    write_evidence(&restart_root, &fixture);
    let mut manifest: PercEvidenceManifest =
        serde_json::from_slice(&fs::read(restart_root.join("evidence_manifest.json")).unwrap())
            .unwrap();
    manifest.retained_receipt_sha256 = sha256_bytes(b"false retained A7 identity");
    manifest.manifest_sha256 = perc_evidence_manifest_digest(&manifest).unwrap();
    fs::write(restart_root.join("evidence_manifest.json"), line(&manifest)).unwrap();
    assert_eq!(
        verify_perc_evidence_directory(&restart_root)
            .unwrap_err()
            .code,
        EocvFaultCode::Restart
    );
    fs::remove_dir_all(restart_root).unwrap();
}

#[test]
fn rehashed_receipt_authority_promotion_refuses_before_retained_equality() {
    let fixture = Fixture::new();
    let root = temporary("authority-promotion");
    write_evidence(&root, &fixture);
    let mut receipt: PercVerificationReceipt =
        serde_json::from_slice(&fs::read(root.join("receipt.json")).unwrap()).unwrap();
    receipt.execution_authorized = true;
    receipt.receipt_sha256 = perc_receipt_digest(&receipt).unwrap();
    fs::write(root.join("receipt.json"), line(&receipt)).unwrap();
    rehash_evidence(&root);
    assert_eq!(
        verify_perc_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::Truth
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_request_field_changes_the_verified_result_or_refuses() {
    let base = Fixture::new();
    let object = serde_json::to_value(&base.request).unwrap();
    assert_eq!(object.as_object().unwrap().len(), 34);
    for (field, value) in object.as_object().unwrap() {
        let mut fixture = base.clone();
        let changed = match field.as_str() {
            "input_class" => json!("externally_supplied_candidate"),
            "expected_confidentiality" => json!("public_metadata"),
            "evidence_references" => json!(["changed_reference"]),
            _ => alter_scalar(value),
        };
        fixture.request = change_typed(&fixture.request, field, changed);
        if field != "request_sha256" {
            fixture.request.request_sha256 = perc_request_digest(&fixture.request).unwrap();
        }
        match fixture.verify() {
            Err(_) => {}
            Ok(receipt) => {
                assert_ne!(
                    receipt.request_sha256, base.request.request_sha256,
                    "{field}"
                );
                assert!(
                    !receipt.correspondence_account.all_correspondence_matches,
                    "unchecked request field {field}"
                );
            }
        }
    }
}

#[test]
fn every_receipt_field_is_reconstructed_and_cannot_be_promoted() {
    let fixture = Fixture::new();
    let receipt = fixture.verify().unwrap();
    let object = serde_json::to_value(&receipt).unwrap();
    assert_eq!(object.as_object().unwrap().len(), 63);
    for (field, value) in object.as_object().unwrap() {
        let changed = match field.as_str() {
            "a6_receipt" => {
                let mut nested = value.clone();
                nested["execution_authorized"] = json!(true);
                nested
            }
            "correspondence_account" => {
                let mut account = value.clone();
                account["opaque_reference_matches"] = json!(false);
                account
            }
            "effect_account" => {
                let mut effect = value.clone();
                effect["filesystem_mutation_count"] = json!(1);
                effect
            }
            "evidence_references" => json!(["changed_reference"]),
            "confidentiality" => json!("public_metadata"),
            "input_class" => json!("externally_supplied_candidate"),
            "receipt_sha256" => alter_scalar(value),
            _ => alter_scalar(value),
        };
        let mut substituted: PercVerificationReceipt = change_typed(&receipt, field, changed);
        if field != "receipt_sha256" {
            substituted.receipt_sha256 = perc_receipt_digest(&substituted).unwrap();
        }
        assert!(
            validate_perc_receipt(
                &fixture.request,
                &fixture.predecessor(),
                &fixture.raw_envelope,
                &substituted,
            )
            .is_err(),
            "unchecked receipt field {field}"
        );
    }
}

#[test]
fn every_envelope_field_changes_the_verified_result_or_refuses() {
    let base = Fixture::new();
    let baseline_receipt = base.verify().unwrap();
    let object = serde_json::to_value(&base.envelope).unwrap();
    assert_eq!(object.as_object().unwrap().len(), 16);
    for (field, value) in object.as_object().unwrap() {
        let changed = match field.as_str() {
            "envelope_uuid" => json!("00000000-0000-0000-0000-000000000000"),
            "confidentiality" => json!("public_metadata"),
            "input_class" => json!("externally_supplied_candidate"),
            "evidence_references" => json!(["changed_reference"]),
            _ => alter_scalar(value),
        };
        let mut fixture = base.clone();
        fixture.envelope = change_typed(&fixture.envelope, field, changed);
        if field != "envelope_sha256" {
            fixture.envelope.envelope_sha256 = perc_envelope_digest(&fixture.envelope).unwrap();
        }
        fixture.raw_envelope = serde_json::to_vec(&fixture.envelope).unwrap();
        fixture.request.expected_envelope_bytes = fixture.raw_envelope.len() as u64;
        fixture.request.expected_envelope_raw_sha256 = sha256_bytes(&fixture.raw_envelope);
        fixture.request.expected_envelope_sha256 = fixture.envelope.envelope_sha256.clone();
        fixture.request.request_sha256 = perc_request_digest(&fixture.request).unwrap();
        match fixture.verify() {
            Err(_) => {}
            Ok(receipt) => {
                assert_ne!(
                    receipt, baseline_receipt,
                    "unchecked envelope field {field}"
                );
                assert!(
                    !receipt.correspondence_account.all_correspondence_matches,
                    "unchecked envelope field {field}"
                );
            }
        }
    }
}

#[test]
fn canonical_envelope_request_and_receipt_framing_refuse() {
    let fixture = Fixture::new();
    let envelope = to_perc_envelope_machine_form(&fixture.envelope).unwrap();
    let request = to_perc_request_machine_form(&fixture.request).unwrap();
    let receipt_value = fixture.verify().unwrap();
    let receipt = to_perc_receipt_machine_form(
        &fixture.request,
        &fixture.predecessor(),
        &fixture.raw_envelope,
        &receipt_value,
    )
    .unwrap();
    for (kind, text) in [
        ("envelope", &envelope),
        ("request", &request),
        ("receipt", &receipt),
    ] {
        for altered in [
            format!(" {text}"),
            format!("{text} "),
            format!("\u{feff}{text}"),
            format!("{text}\r\n"),
            format!("{text}{{}}"),
            text.replacen('{', "{\"unknown\":true,", 1),
            text.replacen('{', "{\"profile\":\"duplicate\",", 1),
            text.replacen("profile", "pro\\u0066ile", 1),
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(text).unwrap()).unwrap(),
            rotate_first_field(text),
        ] {
            let refused = match kind {
                "envelope" => from_perc_envelope_machine_form(&altered).is_err(),
                "request" => from_perc_request_machine_form(&altered).is_err(),
                _ => from_perc_receipt_machine_form(
                    &fixture.request,
                    &fixture.predecessor(),
                    &fixture.raw_envelope,
                    &altered,
                )
                .is_err(),
            };
            assert!(refused, "noncanonical {kind}");
        }
    }
}

#[test]
fn bounded_reference_and_structural_forms_refuse() {
    let base = Fixture::new();
    for references in [
        Vec::new(),
        (0..49).map(|index| format!("r{index}")).collect(),
        vec!["duplicate".to_owned(); 2],
        vec!["unsafe/reference".to_owned()],
    ] {
        let mut fixture = base.clone();
        fixture.request.evidence_references = references;
        fixture.request.request_sha256 = perc_request_digest(&fixture.request).unwrap();
        assert!(fixture.verify().is_err());
    }
    for references in [
        Vec::new(),
        (0..49).map(|index| format!("r{index}")).collect(),
        vec!["duplicate".to_owned(); 2],
        vec!["unsafe:reference".to_owned()],
    ] {
        let mut fixture = base.clone();
        fixture.envelope.evidence_references = references;
        fixture.bind_envelope_raw();
        assert!(fixture.verify().is_err());
    }
    let mut fixture = base.clone();
    fixture.envelope.opaque_reference = "x".repeat(128);
    fixture.bind_envelope_raw();
    assert_eq!(
        fixture.verify().unwrap().effect_account,
        TwvEffectAccount::default()
    );
    fixture.envelope.opaque_reference.push('x');
    fixture.bind_envelope_raw();
    assert_eq!(fixture.verify().unwrap_err().code, EocvFaultCode::Shape);

    let mut deep = json!(0);
    for _ in 0..33 {
        deep = json!({"x": deep});
    }
    assert!(from_perc_envelope_machine_form(&deep.to_string()).is_err());
    let wide: serde_json::Map<String, Value> = (0..4097)
        .map(|index| (format!("f{index}"), json!(index)))
        .collect();
    assert!(from_perc_request_machine_form(&Value::Object(wide).to_string()).is_err());
    assert!(from_perc_request_machine_form(&" ".repeat(PERC_MAX_FORM_BYTES + 1)).is_err());
}

#[test]
fn every_semantic_payload_tamper_refuses_after_outer_manifest_rehash() {
    let fixture = Fixture::new();
    let root = temporary("all-semantic-payloads");
    write_evidence(&root, &fixture);
    let names = [&PERC_EVIDENCE_FILES[..25], &PERC_EVIDENCE_FILES[26..29]].concat();
    assert_eq!(names.len(), 28);
    for name in names {
        let original = fs::read(root.join(name)).unwrap();
        let text = std::str::from_utf8(&original)
            .unwrap()
            .replacen('{', "{\"unknown\":0,", 1);
        fs::write(root.join(name), text).unwrap();
        rehash_evidence(&root);
        assert!(verify_perc_evidence_directory(&root).is_err(), "{name}");
        fs::write(root.join(name), original).unwrap();
        rehash_evidence(&root);
    }
    verify_perc_evidence_directory(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn embedded_a6_manifest_is_retained_but_not_semantic_authority() {
    let fixture = Fixture::new();
    let root = temporary("embedded-a6-manifest");
    write_evidence(&root, &fixture);
    let name = "a6_evidence_manifest.json";
    let text = std::str::from_utf8(&fs::read(root.join(name)).unwrap())
        .unwrap()
        .replacen('{', "{\"untrusted_note\":true,", 1);
    fs::write(root.join(name), text).unwrap();
    rehash_evidence(&root);
    assert_eq!(
        verify_perc_evidence_directory(&root).unwrap().receipt,
        fixture.verify().unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn all_manifest_fields_coordinates_and_canonical_framing_are_checked() {
    let fixture = Fixture::new();
    let root = temporary("manifest");
    write_evidence(&root, &fixture);
    let original = fs::read(root.join("evidence_manifest.json")).unwrap();
    let baseline: PercEvidenceManifest = serde_json::from_slice(&original).unwrap();
    let fields = serde_json::to_value(&baseline).unwrap();
    assert_eq!(fields.as_object().unwrap().len(), 16);
    for (field, value) in fields.as_object().unwrap() {
        let changed = if field == "manifest_uuid" {
            json!("00000000-0000-0000-0000-000000000000")
        } else {
            alter_scalar(value)
        };
        let mut manifest: PercEvidenceManifest = change_typed(&baseline, field, changed);
        if field != "manifest_sha256" {
            manifest.manifest_sha256 = perc_evidence_manifest_digest(&manifest).unwrap();
        }
        fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
        assert!(
            verify_perc_evidence_directory(&root).is_err(),
            "manifest {field}"
        );
    }
    for mode in 0..9 {
        let mut manifest = baseline.clone();
        match mode {
            0 => manifest.artifacts.swap(0, 1),
            1 => manifest.artifacts[0].path = "../outside".to_owned(),
            2 => manifest.artifacts[0].path = "C:/outside".to_owned(),
            3 => manifest.artifacts[0].path = manifest.artifacts[1].path.clone(),
            4 => manifest.artifacts.push(manifest.artifacts[0].clone()),
            5 => manifest.artifacts[0].bytes = u64::MAX,
            6 => manifest.artifacts[0].sha256 = sha256_bytes(b"wrong artifact bytes"),
            7 => manifest.total_artifact_bytes = u64::MAX,
            _ => manifest.artifacts[0].path = "subfolder/../predecessor_request.json".to_owned(),
        }
        manifest.manifest_sha256 = perc_evidence_manifest_digest(&manifest).unwrap();
        fs::write(root.join("evidence_manifest.json"), line(&manifest)).unwrap();
        assert!(
            verify_perc_evidence_directory(&root).is_err(),
            "artifact coordinate {mode}"
        );
    }
    let payload = original.strip_suffix(b"\n").unwrap();
    let text = std::str::from_utf8(payload).unwrap();
    let pretty = serde_json::to_string_pretty(&baseline).unwrap();
    for altered in [
        [b" ".as_slice(), original.as_slice()].concat(),
        [b"\xef\xbb\xbf".as_slice(), original.as_slice()].concat(),
        [payload, b"\r\n"].concat(),
        [original.as_slice(), b"\n"].concat(),
        [pretty.as_bytes(), b"\n"].concat(),
        [rotate_first_field(text).as_bytes(), b"\n"].concat(),
    ] {
        fs::write(root.join("evidence_manifest.json"), altered).unwrap();
        assert!(verify_perc_evidence_directory(&root).is_err());
    }
    fs::write(root.join("evidence_manifest.json"), original).unwrap();
    verify_perc_evidence_directory(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn evidence_membership_framing_cli_arguments_and_resource_bounds_refuse() {
    let fixture = Fixture::new();
    for mode in 0..8 {
        let root = temporary("membership");
        write_evidence(&root, &fixture);
        let name = "observation_bundle.json";
        match mode {
            0 => fs::remove_file(root.join(name)).unwrap(),
            1 => fs::write(root.join("extra.json"), b"{}\n").unwrap(),
            2 => {
                fs::remove_file(root.join("receipt.json")).unwrap();
                fs::create_dir(root.join("receipt.json")).unwrap();
            }
            3 => fs::write(root.join(name), b"").unwrap(),
            _ => {
                let mut bytes = fs::read(root.join(name)).unwrap();
                match mode {
                    4 => {
                        bytes.pop();
                    }
                    5 => bytes.push(b'\n'),
                    6 => bytes.insert(bytes.len() - 1, b'\r'),
                    _ => {
                        bytes.splice(0..0, [0xef, 0xbb, 0xbf]);
                    }
                };
                fs::write(root.join(name), bytes).unwrap();
                rehash_evidence(&root);
            }
        }
        let output = Command::new(EVIDENCE_CLI).arg(&root).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "mode {mode}");
        assert!(output.stdout.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    for args in [vec![], vec!["x"; 26], vec!["x"; 28], vec!["x"; 29]] {
        let output = Command::new(CLI).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    for args in [vec![], vec!["x", "y"], vec!["x", "y", "z"]] {
        let output = Command::new(EVIDENCE_CLI).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }

    let root = temporary("resource-bounds");
    write_evidence(&root, &fixture);
    let relative_names = [&PERC_EVIDENCE_FILES[..25], &PERC_EVIDENCE_FILES[26..28]].concat();
    let output = Command::new(CLI)
        .current_dir(&root)
        .args(&relative_names)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(output.stdout, line(&fixture.verify().unwrap()));
    let paths = explicit_paths(&root);
    let mut duplicate = paths.clone();
    duplicate[1] = duplicate[0].clone();
    assert!(verify_perc_payload_paths(&duplicate).is_err());

    fs::write(
        root.join("observation_bundle.json"),
        vec![b'x'; PERC_MAX_FORM_BYTES + 2],
    )
    .unwrap();
    assert_eq!(
        verify_perc_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Size
    );
    assert_eq!(
        verify_perc_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::Size
    );

    let aggregate_file_bytes = (PERC_MAX_EVIDENCE_BYTES / 27 + 1) as usize;
    let aggregate = vec![b'x'; aggregate_file_bytes];
    for name in PERC_EVIDENCE_FILES {
        fs::write(root.join(name), &aggregate).unwrap();
    }
    assert_eq!(
        verify_perc_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Size
    );
    assert_eq!(
        verify_perc_evidence_directory(&root).unwrap_err().code,
        EocvFaultCode::Size
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_junction_directory_and_ancestor_refuse_without_target_changes() {
    let fixture = Fixture::new();
    let root = temporary("junction");
    write_evidence(&root, &fixture);
    let junction = root.join("linked");
    assert!(
        !root
            .to_string_lossy()
            .chars()
            .any(|character| "&|<>^%!\"\r\n".contains(character))
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
        verify_perc_evidence_directory(&junction).unwrap_err().code,
        EocvFaultCode::Path
    );
    assert_eq!(
        verify_perc_payload_paths(&explicit_paths(&junction))
            .unwrap_err()
            .code,
        EocvFaultCode::Path
    );
    fs::remove_dir(&junction).expect("unlink only the test-owned junction");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 30);
    verify_perc_evidence_directory(&root).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn direct_symlink_inputs_refuse() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let root = temporary("symlink");
    write_evidence(&root, &fixture);
    let target = root.join("observation_bundle.json");
    let link = root.join("bundle-link.json");
    symlink(&target, &link).unwrap();
    let mut paths = explicit_paths(&root);
    paths[22] = link;
    assert_eq!(
        verify_perc_payload_paths(&paths).unwrap_err().code,
        EocvFaultCode::Path
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn self_digest_domains_and_canonical_byte_order_are_explicit() {
    let fixture = Fixture::new();
    let mut envelope = fixture.envelope.clone();
    envelope.envelope_sha256 = empty();
    let mut bytes = b"cantor.b1.private-execution-permit-reference.envelope.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&envelope).unwrap());
    assert_eq!(
        perc_envelope_digest(&fixture.envelope).unwrap(),
        sha256_bytes(&bytes)
    );

    let mut request = fixture.request.clone();
    request.request_sha256 = empty();
    let mut bytes = b"cantor.b1.private-execution-permit-reference.request.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&request).unwrap());
    assert_eq!(
        perc_request_digest(&fixture.request).unwrap(),
        sha256_bytes(&bytes)
    );

    let receipt = fixture.verify().unwrap();
    let mut normalized_receipt = receipt.clone();
    normalized_receipt.receipt_sha256 = empty();
    let mut bytes = b"cantor.b1.private-execution-permit-reference.receipt.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&normalized_receipt).unwrap());
    assert_eq!(perc_receipt_digest(&receipt).unwrap(), sha256_bytes(&bytes));

    let root = temporary("digest-domains");
    write_evidence(&root, &fixture);
    let manifest: PercEvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence_manifest.json")).unwrap()).unwrap();
    let mut normalized_manifest = manifest.clone();
    normalized_manifest.manifest_sha256 = empty();
    let mut bytes = b"cantor.b1.private-execution-permit-reference.evidence-manifest.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&normalized_manifest).unwrap());
    assert_eq!(
        perc_evidence_manifest_digest(&manifest).unwrap(),
        sha256_bytes(&bytes)
    );
    let form = to_perc_evidence_manifest_machine_form(&manifest).unwrap();
    assert_eq!(line(&manifest), [form.as_bytes(), b"\n"].concat());
    assert_eq!(
        line(&manifest),
        fs::read(root.join("evidence_manifest.json")).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn production_has_no_effect_or_producer_capability() {
    let core = include_str!("../src/b1_private_execution_permit_reference_correspondence.rs");
    let evidence =
        include_str!("../src/b1_private_execution_permit_reference_correspondence_evidence.rs");
    for forbidden in [
        "unsafe {",
        "SigningKey",
        "std::process",
        "std::env",
        "SystemTime::now",
        "TcpStream",
        "UdpSocket",
        ".write(true)",
        ".create(true)",
        "fs::write",
        "remove_file(",
        "remove_dir(",
        "Command::new",
        "reqwest",
        "git2",
        "rmcp",
        "llama",
        "produce_provider_free_evidence",
        "support/eocv_predecessor_fixture",
    ] {
        assert!(!core.contains(forbidden), "core {forbidden}");
        assert!(!evidence.contains(forbidden), "evidence {forbidden}");
    }
    assert!(core.contains("verify_eocv_expected_observation("));
    assert!(evidence.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
}

#[test]
fn raw_resource_limit_precedes_expensive_predecessor_replay() {
    let mut fixture = Fixture::new();
    fixture.a6.a5.raw_envelope = b"invalid A5 envelope".to_vec();
    fixture.raw_envelope = vec![b'x'; PERC_MAX_FORM_BYTES + 1];
    assert_eq!(fixture.verify().unwrap_err().code, EocvFaultCode::Size);
}

#[test]
#[ignore = "test-owned fixture producer: explicit fresh output directory required"]
fn produce_provider_free_evidence() {
    let root = std::env::var_os("CANTOR_PERC_EVIDENCE_OUTPUT").expect("explicit test output");
    write_evidence(Path::new(&root), &Fixture::new());
}

#[test]
fn substituted_a6_receipt_refuses_complete_predecessor_replay() {
    let mut fixture = Fixture::new();
    fixture.a6_receipt.production_authority_claimed = true;
    let error = fixture.verify().expect_err("tampered A6 receipt");
    assert_eq!(error.code, EocvFaultCode::Predecessor);
}
