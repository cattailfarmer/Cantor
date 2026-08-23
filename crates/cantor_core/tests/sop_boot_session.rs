use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    AdmissionDecision, AdmissionDisposition, CompilationReceipt, ContentDigest, PhaseDisposition,
    ReceiptEvidence, SOP_BOOT_INVOCATION_CONTEXT, SOP_BOOT_SESSION_NON_AUTHORITY,
    SOP_BOOT_SESSION_PROPOSAL_PROFILE, SOP_BOOT_SESSION_REQUEST_PROFILE, SemanticId,
    SopBootCapabilityDenial, SopBootSessionAuthority, SopBootSessionBounds,
    SopBootSessionFaultCode, SopBootSessionLifecycle, SopBootSessionRequest,
    SopRevisionAdmissionBinding, ValidationReceipt, VerificationReceipt, compile_sop_boot_session,
    compute_admission_disposition_digest, compute_compilation_receipt_digest,
    compute_validation_receipt_digest, compute_verification_receipt_digest,
    from_sop_boot_session_proposal_machine_form, from_sop_boot_session_request_machine_form,
    sop_boot_session_proposal_digest, to_sop_boot_session_proposal_machine_form,
    to_sop_boot_session_request_machine_form, validate_sop_boot_session_proposal,
    validate_sop_boot_session_request,
};
use serde_json::{Value, json};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(symbol: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: symbol.to_string().repeat(64),
    }
}

fn empty_digest() -> ContentDigest {
    digest('0')
}

fn evidence(label: &str) -> ReceiptEvidence {
    ReceiptEvidence {
        evidence_refs: [id(label)].into_iter().collect(),
        residuals: BTreeSet::new(),
        diagnostics: BTreeSet::new(),
    }
}

fn boot_sop() -> SopRevisionAdmissionBinding {
    let candidate_ref = id("procedure-candidate:boot-sop-fixture");
    let source_digest = digest('a');
    let mut validation = ValidationReceipt {
        receipt_id: id("validation-receipt:boot-sop-fixture"),
        candidate_ref: candidate_ref.clone(),
        candidate_source_digest: source_digest.clone(),
        validator_ref: id("validator:boot-sop-fixture"),
        profile: "cantor-process-procedure-validation/0.1".to_owned(),
        disposition: PhaseDisposition::Passed,
        evidence: evidence("evidence:validation"),
        receipt_digest: empty_digest(),
    };
    validation.receipt_digest =
        compute_validation_receipt_digest(&validation).expect("validation digest");

    let mut compilation = CompilationReceipt {
        receipt_id: id("compilation-receipt:boot-sop-fixture"),
        candidate_ref: candidate_ref.clone(),
        candidate_source_digest: source_digest.clone(),
        validation_receipt_ref: validation.receipt_id.clone(),
        compiler_ref: id("compiler:boot-sop-fixture"),
        ir_ref: Some(id("ir:boot-sop-fixture")),
        ir_digest: Some(digest('b')),
        disposition: PhaseDisposition::Passed,
        cost_estimate: BTreeMap::from([("instructions".to_owned(), 8)]),
        evidence: evidence("evidence:compilation"),
        receipt_digest: empty_digest(),
    };
    compilation.receipt_digest =
        compute_compilation_receipt_digest(&compilation).expect("compilation digest");

    let mut verification = VerificationReceipt {
        receipt_id: id("verification-receipt:boot-sop-fixture"),
        candidate_ref: candidate_ref.clone(),
        candidate_source_digest: source_digest.clone(),
        compilation_receipt_ref: compilation.receipt_id.clone(),
        verifier_ref: id("verifier:boot-sop-fixture"),
        compiler_ref: compilation.compiler_ref.clone(),
        ir_ref: compilation.ir_ref.clone().expect("IR ref"),
        ir_digest: compilation.ir_digest.clone().expect("IR digest"),
        compiled_procedure_ref: id("procedure:boot-sop-fixture"),
        compiled_procedure_digest: digest('c'),
        anchor_set_digest: digest('d'),
        effect_declaration_digest: digest('e'),
        bound_set_ref: id("bounds:boot-sop-fixture"),
        bounds_digest: digest('f'),
        disposition: PhaseDisposition::Passed,
        evidence: evidence("evidence:verification"),
        receipt_digest: empty_digest(),
    };
    verification.receipt_digest =
        compute_verification_receipt_digest(&verification).expect("verification digest");

    let mut admission = AdmissionDisposition {
        disposition_id: id("admission-disposition:boot-sop-fixture"),
        candidate_ref: candidate_ref.clone(),
        candidate_source_digest: source_digest.clone(),
        validation_receipt_ref: validation.receipt_id.clone(),
        compilation_receipt_ref: compilation.receipt_id.clone(),
        verification_receipt_ref: verification.receipt_id.clone(),
        observer_ref: id("observer:boot-sop-fixture"),
        compiler_ref: compilation.compiler_ref.clone(),
        ir_ref: verification.ir_ref.clone(),
        ir_digest: verification.ir_digest.clone(),
        procedure_ref: verification.compiled_procedure_ref.clone(),
        procedure_digest: verification.compiled_procedure_digest.clone(),
        anchor_set_digest: verification.anchor_set_digest.clone(),
        effect_declaration_digest: verification.effect_declaration_digest.clone(),
        bound_set_ref: verification.bound_set_ref.clone(),
        bounds_digest: verification.bounds_digest.clone(),
        decision: AdmissionDecision::Admit,
        permitted_invocation_contexts: [SOP_BOOT_INVOCATION_CONTEXT.to_owned()]
            .into_iter()
            .collect(),
        revocation_conditions: [
            "admission_revoked",
            "objective_changed",
            "outer_host_identity_changed",
            "sop_revision_changed",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        policy_ref: id("policy:boot-sop-fixture"),
        policy_digest: digest('1'),
        evidence: evidence("evidence:admission"),
        disposition_digest: empty_digest(),
    };
    admission.disposition_digest =
        compute_admission_disposition_digest(&admission).expect("admission digest");

    SopRevisionAdmissionBinding {
        canonical_sop_ref: id("canonical-sop:self-working-fixture"),
        sop_revision_ref: id("sop-revision:self-working-fixture"),
        sop_revision_digest: source_digest,
        satisfaction_signature_ref: id("signature:self-working-fixture"),
        satisfaction_signature_digest: digest('2'),
        procedure_candidate_ref: candidate_ref,
        validation,
        compilation,
        verification,
        admission,
    }
}

fn request() -> SopBootSessionRequest {
    SopBootSessionRequest {
        profile: SOP_BOOT_SESSION_REQUEST_PROFILE.to_owned(),
        boot_request_id: id("boot-request:fixture"),
        proposed_session_id: id("agent-session:fixture"),
        outer_host_id: id("outer-host:fixture"),
        outer_host_identity_envelope_digest: digest('3'),
        boot_sop: boot_sop(),
        objective_ref: id("objective:fixture"),
        objective_digest: digest('4'),
        authority_ref: id("authority:sop-boot-session-p0"),
        authority_digest: digest('5'),
        bounds: SopBootSessionBounds {
            maximum_work_packets: 1,
            maximum_checkpoints: 64,
            maximum_update_proposals: 32,
            session_timeout_seconds: 86_400,
        },
        evidence_refs: [id("evidence:boot-request")].into_iter().collect(),
        unresolved_account: [
            "objective_not_executed",
            "process_not_launched",
            "sop_bytes_not_observed",
            "workspace_not_admitted",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        non_authority: SOP_BOOT_SESSION_NON_AUTHORITY.to_owned(),
    }
}

fn fresh_request() -> SopBootSessionRequest {
    request()
}

#[test]
fn valid_admitted_sop_proposes_deterministic_nonlaunched_session() {
    let request = request();
    let proposal = compile_sop_boot_session(&request).expect("compile proposal");
    assert_eq!(proposal.profile, SOP_BOOT_SESSION_PROPOSAL_PROFILE);
    assert_eq!(
        proposal.lifecycle,
        SopBootSessionLifecycle::ProposedNotLaunched
    );
    assert_eq!(
        proposal.authority,
        SopBootSessionAuthority::IdentityAndPlanningOnly
    );
    assert_eq!(proposal.capability_denials.len(), 9);
    assert!(
        proposal
            .capability_denials
            .contains(&SopBootCapabilityDenial::SopActivation)
    );
    validate_sop_boot_session_proposal(&request, &proposal).expect("validate proposal");
    assert_eq!(
        proposal,
        compile_sop_boot_session(&request).expect("deterministic replay")
    );

    let request_form = to_sop_boot_session_request_machine_form(&request).expect("request form");
    assert_eq!(
        request,
        from_sop_boot_session_request_machine_form(&request_form).expect("request round trip")
    );
    let proposal_form =
        to_sop_boot_session_proposal_machine_form(&proposal).expect("proposal form");
    assert_eq!(
        proposal,
        from_sop_boot_session_proposal_machine_form(&proposal_form).expect("proposal round trip")
    );
}

#[test]
fn unknown_request_and_proposal_fields_refuse() {
    let request = request();
    let mut request_value = serde_json::to_value(&request).expect("request value");
    request_value
        .as_object_mut()
        .expect("request object")
        .insert("launch".to_owned(), json!(true));
    assert_eq!(
        from_sop_boot_session_request_machine_form(&request_value.to_string())
            .expect_err("unknown request field")
            .code,
        SopBootSessionFaultCode::InvalidMachineForm
    );

    let proposal = compile_sop_boot_session(&request).expect("proposal");
    let mut proposal_value = serde_json::to_value(proposal).expect("proposal value");
    proposal_value
        .as_object_mut()
        .expect("proposal object")
        .insert("running".to_owned(), json!(true));
    assert_eq!(
        from_sop_boot_session_proposal_machine_form(&proposal_value.to_string())
            .expect_err("unknown proposal field")
            .code,
        SopBootSessionFaultCode::InvalidMachineForm
    );
}

#[test]
fn identity_collisions_refuse() {
    let mut request = request();
    request.proposed_session_id = request.outer_host_id.clone();
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("identity collision")
            .code,
        SopBootSessionFaultCode::IdentityCollision
    );

    let mut request = fresh_request();
    request.boot_sop.compilation.receipt_id = request.boot_sop.validation.receipt_id.clone();
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("receipt collision")
            .code,
        SopBootSessionFaultCode::InvalidRevisionBinding
    );
}

#[test]
fn revision_candidate_and_source_substitutions_refuse() {
    let mut request = request();
    request.boot_sop.validation.candidate_ref = id("procedure-candidate:substitute");
    request.boot_sop.validation.receipt_digest =
        compute_validation_receipt_digest(&request.boot_sop.validation).expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("candidate substitution")
            .code,
        SopBootSessionFaultCode::InvalidRevisionBinding
    );

    let mut request = fresh_request();
    request.boot_sop.verification.candidate_source_digest = digest('9');
    request.boot_sop.verification.receipt_digest =
        compute_verification_receipt_digest(&request.boot_sop.verification)
            .expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("source substitution")
            .code,
        SopBootSessionFaultCode::InvalidRevisionBinding
    );
}

#[test]
fn refused_or_incomplete_receipt_stage_refuses() {
    let mut request = request();
    request.boot_sop.validation.disposition = PhaseDisposition::Refused;
    request.boot_sop.validation.receipt_digest =
        compute_validation_receipt_digest(&request.boot_sop.validation).expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("refused validation")
            .code,
        SopBootSessionFaultCode::InvalidAdmissionChain
    );

    let mut request = fresh_request();
    request.boot_sop.compilation.ir_ref = None;
    request.boot_sop.compilation.ir_digest = None;
    request.boot_sop.compilation.receipt_digest =
        compute_compilation_receipt_digest(&request.boot_sop.compilation)
            .expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("missing IR")
            .code,
        SopBootSessionFaultCode::InvalidAdmissionChain
    );
}

#[test]
fn admission_predecessor_and_semantic_substitutions_refuse() {
    let mut request = request();
    request.boot_sop.compilation.validation_receipt_ref = id("validation-receipt:substitute");
    request.boot_sop.compilation.receipt_digest =
        compute_compilation_receipt_digest(&request.boot_sop.compilation)
            .expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("predecessor substitution")
            .code,
        SopBootSessionFaultCode::InvalidAdmissionChain
    );

    let mut request = fresh_request();
    request.boot_sop.admission.procedure_digest = digest('8');
    request.boot_sop.admission.disposition_digest =
        compute_admission_disposition_digest(&request.boot_sop.admission)
            .expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("procedure substitution")
            .code,
        SopBootSessionFaultCode::InvalidAdmissionChain
    );
}

#[test]
fn receipt_digest_tampering_refuses() {
    let mut request = request();
    request.boot_sop.verification.receipt_digest = digest('7');
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("receipt digest tamper")
            .code,
        SopBootSessionFaultCode::InvalidAdmissionChain
    );
}

#[test]
fn receipt_evidence_residual_or_absence_refuses() {
    let mut request = request();
    request.boot_sop.validation.evidence.evidence_refs.clear();
    request.boot_sop.validation.receipt_digest =
        compute_validation_receipt_digest(&request.boot_sop.validation).expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("missing receipt evidence")
            .code,
        SopBootSessionFaultCode::InvalidEvidence
    );

    let mut request = fresh_request();
    request
        .boot_sop
        .admission
        .evidence
        .residuals
        .insert("unresolved".to_owned());
    request.boot_sop.admission.disposition_digest =
        compute_admission_disposition_digest(&request.boot_sop.admission)
            .expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("receipt residual")
            .code,
        SopBootSessionFaultCode::InvalidEvidence
    );
}

#[test]
fn boot_context_and_revocation_substitutions_refuse() {
    let mut request = request();
    request.boot_sop.admission.permitted_invocation_contexts =
        ["process_launch".to_owned()].into_iter().collect();
    request.boot_sop.admission.disposition_digest =
        compute_admission_disposition_digest(&request.boot_sop.admission)
            .expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("context substitution")
            .code,
        SopBootSessionFaultCode::InvalidAdmissionChain
    );

    let mut request = fresh_request();
    request
        .boot_sop
        .admission
        .revocation_conditions
        .remove("sop_revision_changed");
    request.boot_sop.admission.disposition_digest =
        compute_admission_disposition_digest(&request.boot_sop.admission)
            .expect("rehashed mutation");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("revocation removal")
            .code,
        SopBootSessionFaultCode::InvalidAdmissionChain
    );
}

#[test]
fn every_bound_class_refuses_outside_its_ceiling() {
    for mutate in [
        |bounds: &mut SopBootSessionBounds| bounds.maximum_work_packets = 2,
        |bounds: &mut SopBootSessionBounds| bounds.maximum_checkpoints = 0,
        |bounds: &mut SopBootSessionBounds| bounds.maximum_update_proposals = 33,
        |bounds: &mut SopBootSessionBounds| bounds.session_timeout_seconds = 86_401,
    ] {
        let mut request = request();
        mutate(&mut request.bounds);
        assert_eq!(
            validate_sop_boot_session_request(&request)
                .expect_err("invalid bound")
                .code,
            SopBootSessionFaultCode::InvalidBounds
        );
    }
}

#[test]
fn request_evidence_unresolved_and_nonauthority_substitutions_refuse() {
    let mut request = request();
    request.evidence_refs.clear();
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("missing evidence")
            .code,
        SopBootSessionFaultCode::InvalidEvidence
    );

    let mut request = fresh_request();
    request.unresolved_account.remove("workspace_not_admitted");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("unresolved removal")
            .code,
        SopBootSessionFaultCode::InvalidUnresolvedAccount
    );

    let mut request = fresh_request();
    request.non_authority.push_str(" Authorized.");
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("nonauthority mutation")
            .code,
        SopBootSessionFaultCode::InvalidAuthority
    );
}

#[test]
fn malformed_digest_refuses() {
    let mut request = request();
    request.objective_digest.value = "A".repeat(64);
    assert_eq!(
        validate_sop_boot_session_request(&request)
            .expect_err("upper-case digest")
            .code,
        SopBootSessionFaultCode::InvalidDigest
    );
}

#[test]
fn proposal_request_output_and_digest_tampering_refuse() {
    let request = request();
    let mut proposal = compile_sop_boot_session(&request).expect("proposal");
    proposal.request.objective_digest = digest('6');
    assert_eq!(
        validate_sop_boot_session_proposal(&request, &proposal)
            .expect_err("request substitution")
            .code,
        SopBootSessionFaultCode::InvalidCorrespondence
    );

    let mut proposal = compile_sop_boot_session(&request).expect("proposal");
    proposal.request_digest = digest('6');
    assert_eq!(
        validate_sop_boot_session_proposal(&request, &proposal)
            .expect_err("request digest")
            .code,
        SopBootSessionFaultCode::InvalidDigest
    );

    let mut proposal = compile_sop_boot_session(&request).expect("proposal");
    proposal.proposal_digest = digest('6');
    assert_eq!(
        validate_sop_boot_session_proposal(&request, &proposal)
            .expect_err("proposal digest")
            .code,
        SopBootSessionFaultCode::InvalidDigest
    );
}

#[test]
fn proposal_denial_lifecycle_and_authority_tampering_refuse() {
    let request = request();
    let mut proposal = compile_sop_boot_session(&request).expect("proposal");
    proposal
        .capability_denials
        .remove(&SopBootCapabilityDenial::WorkspaceMutation);
    proposal.proposal_digest =
        sop_boot_session_proposal_digest(&proposal).expect("rehashed proposal");
    assert_eq!(
        validate_sop_boot_session_proposal(&request, &proposal)
            .expect_err("denial removal")
            .code,
        SopBootSessionFaultCode::InvalidAuthority
    );

    let mut value = serde_json::to_value(compile_sop_boot_session(&request).expect("proposal"))
        .expect("proposal value");
    value["lifecycle"] = json!("running");
    assert_eq!(
        from_sop_boot_session_proposal_machine_form(&value.to_string())
            .expect_err("lifecycle widening")
            .code,
        SopBootSessionFaultCode::InvalidMachineForm
    );

    let mut value = serde_json::to_value(compile_sop_boot_session(&request).expect("proposal"))
        .expect("proposal value");
    value["authority"] = json!("workspace_mutation");
    assert_eq!(
        from_sop_boot_session_proposal_machine_form(&value.to_string())
            .expect_err("authority widening")
            .code,
        SopBootSessionFaultCode::InvalidMachineForm
    );
}

#[test]
fn trailing_machine_content_refuses() {
    let request_form = to_sop_boot_session_request_machine_form(&request()).expect("request form");
    assert_eq!(
        from_sop_boot_session_request_machine_form(&format!("{request_form} true"))
            .expect_err("trailing content")
            .code,
        SopBootSessionFaultCode::InvalidMachineForm
    );
}

#[test]
fn proposal_machine_form_is_canonical_json_object() {
    let proposal = compile_sop_boot_session(&request()).expect("proposal");
    let form = to_sop_boot_session_proposal_machine_form(&proposal).expect("proposal form");
    let value: Value = serde_json::from_str(&form).expect("JSON object");
    assert!(value.is_object());
    assert_eq!(value["lifecycle"], json!("proposed_not_launched"));
}
