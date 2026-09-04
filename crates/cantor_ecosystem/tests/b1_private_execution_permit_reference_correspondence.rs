//! Full A7 replay over the governed A6 test fixture; no private permit material.
#[allow(dead_code)]
#[path = "support/eocv_predecessor_fixture.rs"]
mod upstream_fixture;

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::*;

fn empty() -> ContentDigest {
    sha256_bytes(b"")
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
fn substituted_a6_receipt_refuses_complete_predecessor_replay() {
    let mut fixture = Fixture::new();
    fixture.a6_receipt.production_authority_claimed = true;
    let error = fixture.verify().expect_err("tampered A6 receipt");
    assert_eq!(error.code, EocvFaultCode::Predecessor);
}
