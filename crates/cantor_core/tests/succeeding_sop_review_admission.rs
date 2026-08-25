#[path = "succeeding_sop_proposal.rs"]
mod proposal_fixture;

use std::{
    collections::BTreeSet,
    io::Write,
    process::{Command, Stdio},
};

use cantor_core::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn admission_request(
    status: SucceedingSopReviewerPolicyUseStatus,
) -> SucceedingSopReviewAdmissionRequest {
    let proposal = compile_succeeding_sop(&proposal_fixture::ready_request()).expect("proposal");
    let proposal_verification =
        verify_succeeding_sop_proposal(&proposal).expect("proposal verification");
    let key = SigningKey::from_bytes(&[101_u8; 32]);
    let mut reviewer_policy = SucceedingSopReviewerPolicy {
        profile: SUCCEEDING_SOP_REVIEWER_POLICY_PROFILE.to_owned(),
        use_status: status,
        policy_ref: id("review-policy:swa-06b1-fixture"),
        reviewer_ref: id("reviewer:independent-fixture"),
        verifying_key_hex: encode_hex(&key.verifying_key().to_bytes()),
        allowed_proposal_profile: SUCCEEDING_SOP_PROPOSAL_PROFILE.to_owned(),
        satisfaction_signature_protocol_uuid: SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROTOCOL_UUID
            .to_owned(),
        governance_evidence_refs: [id("evidence:review-policy-governance")]
            .into_iter()
            .collect(),
        non_authority: SUCCEEDING_SOP_REVIEW_ADMISSION_NON_AUTHORITY.to_owned(),
        policy_digest: empty_digest(),
    };
    reviewer_policy.policy_digest =
        succeeding_sop_reviewer_policy_digest(&reviewer_policy).expect("policy digest");

    let mut source_preservation = SucceedingSopSourcePreservationRecord {
        profile: SUCCEEDING_SOP_SOURCE_PRESERVATION_PROFILE.to_owned(),
        preservation_ref: id("source-preservation:swa-06b1-fixture"),
        source_snapshot_ref: id("source-snapshot:swa-06b1-fixture"),
        source_path:
            "source_documents/reviewed_succeeding_sop/Cantor_Fixture_Succeeding_SOP_Source.sop"
                .to_owned(),
        source_subject: proposal.source_subject.clone(),
        source_sha256: proposal.source_sha256.clone(),
        source_bytes: proposal.source_text.len() as u64,
        proposal_digest: proposal.proposal_digest.clone(),
        preserved: true,
        immutable: true,
        evidence_refs: [id("evidence:source-preservation")].into_iter().collect(),
        preservation_digest: empty_digest(),
    };
    source_preservation.preservation_digest =
        succeeding_sop_source_preservation_digest(&source_preservation)
            .expect("preservation digest");

    let mut payload = SucceedingSopReviewPayload {
        profile: SUCCEEDING_SOP_REVIEW_PAYLOAD_PROFILE.to_owned(),
        satisfaction_signature_protocol_uuid: SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROTOCOL_UUID
            .to_owned(),
        policy_ref: reviewer_policy.policy_ref.clone(),
        policy_digest: reviewer_policy.policy_digest.clone(),
        reviewer_ref: reviewer_policy.reviewer_ref.clone(),
        author_ref: proposal.author_ref.clone(),
        proposal_ref: proposal.proposal_ref.clone(),
        request_digest: proposal.request_digest.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        verification_digest: proposal_verification.verification_digest.clone(),
        source_subject: proposal.source_subject.clone(),
        source_sha256: proposal.source_sha256.clone(),
        source_bytes: proposal.source_text.len() as u64,
        unresolved_frontier: proposal.unresolved_frontier.clone(),
        preservation_ref: source_preservation.preservation_ref.clone(),
        preservation_digest: source_preservation.preservation_digest.clone(),
        decision: SucceedingSopReviewDecision::Approved,
        review_checks: SUCCEEDING_SOP_REVIEW_CHECKS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        review_evidence_refs: [id("evidence:independent-semantic-review")]
            .into_iter()
            .collect(),
        payload_digest: empty_digest(),
    };
    payload.payload_digest =
        succeeding_sop_review_payload_digest(&payload).expect("payload digest");
    let signature_hex = encode_hex(
        &key.sign(&succeeding_sop_review_payload_bytes(&payload).expect("payload bytes"))
            .to_bytes(),
    );

    SucceedingSopReviewAdmissionRequest {
        profile: SUCCEEDING_SOP_REVIEW_ADMISSION_REQUEST_PROFILE.to_owned(),
        admission_id: id("review-admission:swa-06b1-fixture"),
        proposal_verification,
        reviewer_policy,
        source_preservation,
        satisfaction_signature: SucceedingSopSatisfactionSignatureEnvelope {
            profile: SUCCEEDING_SOP_SATISFACTION_SIGNATURE_PROFILE.to_owned(),
            payload,
            signature_hex,
        },
        activation_obligations: SUCCEEDING_SOP_ACTIVATION_OBLIGATIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        non_authority: SUCCEEDING_SOP_REVIEW_ADMISSION_NON_AUTHORITY.to_owned(),
    }
}

fn resign_review_payload(request: &mut SucceedingSopReviewAdmissionRequest) {
    request.satisfaction_signature.payload.payload_digest = empty_digest();
    request.satisfaction_signature.payload.payload_digest =
        succeeding_sop_review_payload_digest(&request.satisfaction_signature.payload)
            .expect("payload digest");
    let key = SigningKey::from_bytes(&[101_u8; 32]);
    request.satisfaction_signature.signature_hex = encode_hex(
        &key.sign(
            &succeeding_sop_review_payload_bytes(&request.satisfaction_signature.payload)
                .expect("payload bytes"),
        )
        .to_bytes(),
    );
}

#[test]
fn signed_review_admission_is_deterministic_self_contained_and_physically_ineligible() {
    for status in [
        SucceedingSopReviewerPolicyUseStatus::ExternallyGoverned,
        SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly,
    ] {
        let request = admission_request(status);
        let receipt = admit_succeeding_sop_review(&request).expect("admission");
        assert_eq!(receipt.policy_use_status, status);
        assert_eq!(
            receipt.status,
            SucceedingSopReviewAdmissionStatus::CryptographicallyVerifiedAwaitingPhysicalActivation
        );
        assert_eq!(
            receipt.authority,
            SucceedingSopReviewAdmissionAuthority::ReviewSignatureCorrespondenceOnly
        );
        assert!(receipt.cryptographic_signature_verified);
        assert!(receipt.structural_reviewer_independence_verified);
        assert!(receipt.source_preservation_correspondence_verified);
        assert!(!receipt.semantic_truth_proved);
        assert!(!receipt.policy_governance_proved);
        assert!(!receipt.physical_contact);
        assert!(!receipt.physical_activation_eligible);
        assert_eq!(receipt.verified_checks.len(), 9);
        assert_eq!(receipt.activation_obligations.len(), 6);
        assert_eq!(
            receipt,
            admit_succeeding_sop_review(&request).expect("deterministic replay")
        );

        let request_form =
            to_succeeding_sop_review_admission_request_machine_form(&request).expect("request");
        assert_eq!(
            request,
            from_succeeding_sop_review_admission_request_machine_form(&request_form)
                .expect("request round trip")
        );
        let receipt_form =
            to_succeeding_sop_review_admission_receipt_machine_form(&receipt).expect("receipt");
        assert_eq!(
            receipt,
            from_succeeding_sop_review_admission_receipt_machine_form(&receipt_form)
                .expect("receipt round trip")
        );
    }
}

#[test]
fn reviewer_policy_and_identity_collisions_refuse() {
    let request = admission_request(SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly);
    let collisions = [
        request.proposal_verification.proposal.author_ref.clone(),
        request.proposal_verification.verifier_ref.clone(),
        request
            .proposal_verification
            .proposal
            .selected_step_ref
            .clone(),
        request.source_preservation.preservation_ref.clone(),
        request.admission_id.clone(),
    ];
    for collision in collisions {
        let mut candidate = request.clone();
        candidate.reviewer_policy.reviewer_ref = collision.clone();
        candidate.satisfaction_signature.payload.reviewer_ref = collision;
        assert_eq!(
            validate_succeeding_sop_review_admission_request(&candidate)
                .expect_err("identity collision")
                .code,
            SucceedingSopReviewAdmissionFaultCode::InvalidIdentity
        );
    }

    let mut missing_evidence = request.clone();
    missing_evidence.reviewer_policy.governance_evidence_refs = BTreeSet::new();
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&missing_evidence)
            .expect_err("policy evidence")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidEvidence
    );

    let mut lowercase_key = request;
    lowercase_key.reviewer_policy.verifying_key_hex = lowercase_key
        .reviewer_policy
        .verifying_key_hex
        .to_lowercase();
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&lowercase_key)
            .expect_err("noncanonical key")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidSignature
    );
}

#[test]
fn signature_key_payload_and_protocol_mutations_refuse() {
    let request = admission_request(SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly);

    let mut wrong_key = request.clone();
    wrong_key.reviewer_policy.verifying_key_hex = encode_hex(
        &SigningKey::from_bytes(&[103_u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    wrong_key.reviewer_policy.policy_digest =
        succeeding_sop_reviewer_policy_digest(&wrong_key.reviewer_policy).expect("policy digest");
    wrong_key.satisfaction_signature.payload.policy_digest =
        wrong_key.reviewer_policy.policy_digest.clone();
    wrong_key.satisfaction_signature.payload.payload_digest =
        succeeding_sop_review_payload_digest(&wrong_key.satisfaction_signature.payload)
            .expect("payload digest");
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&wrong_key)
            .expect_err("wrong key")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidSignature
    );

    let mut signature = request.clone();
    signature
        .satisfaction_signature
        .signature_hex
        .replace_range(
            0..1,
            if signature
                .satisfaction_signature
                .signature_hex
                .starts_with('F')
            {
                "E"
            } else {
                "F"
            },
        );
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&signature)
            .expect_err("signature mutation")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidSignature
    );

    let mut protocol = request;
    protocol
        .satisfaction_signature
        .payload
        .satisfaction_signature_protocol_uuid = "00000000-0000-0000-0000-000000000000".to_owned();
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&protocol)
            .expect_err("protocol substitution")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidProtocol
    );
}

#[test]
fn source_preservation_substitution_and_path_escape_refuse() {
    let request = admission_request(SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly);
    for path in [
        "../escape.sop",
        "/source_documents/escape.sop",
        "C:/source_documents/escape.sop",
        "source_documents/../escape.sop",
        "source_documents\\escape.sop",
        "source_documents/escape.txt",
    ] {
        let mut candidate = request.clone();
        candidate.source_preservation.source_path = path.to_owned();
        assert_eq!(
            validate_succeeding_sop_review_admission_request(&candidate)
                .expect_err("path escape")
                .code,
            SucceedingSopReviewAdmissionFaultCode::InvalidPath
        );
    }

    let mut source = request.clone();
    source.source_preservation.source_bytes += 1;
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&source)
            .expect_err("source substitution")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidPreservation
    );

    let mut immutable = request;
    immutable.source_preservation.immutable = false;
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&immutable)
            .expect_err("mutable preservation")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidPreservation
    );
}

#[test]
fn review_frontier_policy_and_authority_laundering_refuse() {
    let request = admission_request(SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly);

    let mut checks = request.clone();
    checks
        .satisfaction_signature
        .payload
        .review_checks
        .remove("source_intent_reviewed");
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&checks)
            .expect_err("review omission")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidReview
    );

    let mut frontier = request.clone();
    frontier
        .satisfaction_signature
        .payload
        .unresolved_frontier
        .clear();
    resign_review_payload(&mut frontier);
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&frontier)
            .expect_err("frontier loss")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidCorrespondence
    );

    let mut policy = request.clone();
    policy.satisfaction_signature.payload.policy_ref = id("review-policy:substituted");
    resign_review_payload(&mut policy);
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&policy)
            .expect_err("policy substitution")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidCorrespondence
    );

    let mut authority = request;
    authority
        .activation_obligations
        .remove("never_self_activate");
    assert_eq!(
        validate_succeeding_sop_review_admission_request(&authority)
            .expect_err("activation laundering")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidAuthority
    );
}

#[test]
fn receipt_correspondence_and_digest_laundering_refuse() {
    let request = admission_request(SucceedingSopReviewerPolicyUseStatus::ExternallyGoverned);
    let receipt = admit_succeeding_sop_review(&request).expect("receipt");

    let mut eligibility = receipt.clone();
    eligibility.physical_activation_eligible = true;
    assert_eq!(
        validate_succeeding_sop_review_admission_receipt(&eligibility)
            .expect_err("eligibility laundering")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidCorrespondence
    );

    let mut semantic_truth = receipt.clone();
    semantic_truth.semantic_truth_proved = true;
    assert_eq!(
        validate_succeeding_sop_review_admission_receipt(&semantic_truth)
            .expect_err("semantic laundering")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidCorrespondence
    );

    let mut digest = receipt;
    digest.receipt_digest.value.replace_range(
        0..1,
        if digest.receipt_digest.value.starts_with('f') {
            "e"
        } else {
            "f"
        },
    );
    assert_eq!(
        validate_succeeding_sop_review_admission_receipt(&digest)
            .expect_err("digest mutation")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidDigest
    );
}

#[test]
fn unknown_fields_and_oversized_machine_forms_refuse() {
    let request = admission_request(SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly);
    let mut value = serde_json::to_value(&request).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .insert("unexpected".to_owned(), Value::Bool(true));
    assert_eq!(
        from_succeeding_sop_review_admission_request_machine_form(
            &serde_json::to_string(&value).expect("form")
        )
        .expect_err("unknown field")
        .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidMachineForm
    );

    let oversized = "x".repeat(SUCCEEDING_SOP_REVIEW_ADMISSION_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_succeeding_sop_review_admission_request_machine_form(&oversized)
            .expect_err("oversized")
            .code,
        SucceedingSopReviewAdmissionFaultCode::InvalidBound
    );
}

#[test]
fn cli_admits_and_replays_receipt_without_output_path() {
    let request = admission_request(SucceedingSopReviewerPolicyUseStatus::SyntheticFixtureOnly);
    let request_form =
        to_succeeding_sop_review_admission_request_machine_form(&request).expect("request form");
    let admit = invoke_cli("admit", &request_form, &[]);
    assert!(
        admit.status.success(),
        "{}",
        String::from_utf8_lossy(&admit.stderr)
    );
    let receipt_form = String::from_utf8(admit.stdout).expect("stdout");
    let receipt =
        from_succeeding_sop_review_admission_receipt_machine_form(receipt_form.trim_end())
            .expect("compiled receipt");
    assert!(receipt.cryptographic_signature_verified);
    assert!(!receipt.physical_activation_eligible);

    let verify = invoke_cli("verify", receipt_form.trim_end(), &[]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(verify.stdout, receipt_form.as_bytes());

    let extra = invoke_cli("admit", &request_form, &["forbidden-output.json"]);
    assert!(!extra.status.success());
}

#[test]
fn production_surface_has_no_signing_physical_or_activation_route() {
    let module = include_str!("../src/succeeding_sop_review_admission.rs");
    let cli = include_str!("../src/bin/cantor-succeeding-sop-review-admission.rs");
    for forbidden in [
        "SigningKey",
        ".sign(",
        "std::fs",
        "std::process::Command",
        "TcpStream",
        "UdpSocket",
        "unsafe {",
        "SystemTime",
        "std::env::var",
        "create_dir",
        "fs::write",
    ] {
        assert!(!module.contains(forbidden), "module contains {forbidden}");
        assert!(!cli.contains(forbidden), "CLI contains {forbidden}");
    }
}

fn invoke_cli(operation: &str, input: &str, extra_arguments: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cantor-succeeding-sop-review-admission"))
        .arg(operation)
        .args(extra_arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write input");
    child.wait_with_output().expect("CLI output")
}
