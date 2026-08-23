use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;
use serde_json::json;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn digest(symbol: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: symbol.to_string().repeat(64),
    }
}

fn evidence(label: &str) -> ReceiptEvidence {
    ReceiptEvidence {
        evidence_refs: [id(label)].into_iter().collect(),
        residuals: BTreeSet::new(),
        diagnostics: BTreeSet::new(),
    }
}

fn boot_proposal() -> SopBootSessionProposal {
    let candidate = id("candidate:owp-boot");
    let source = digest('a');
    let mut validation = ValidationReceipt {
        receipt_id: id("validation:owp-boot"),
        candidate_ref: candidate.clone(),
        candidate_source_digest: source.clone(),
        validator_ref: id("validator:owp-boot"),
        profile: "validation/fixture".to_owned(),
        disposition: PhaseDisposition::Passed,
        evidence: evidence("evidence:owp-validation"),
        receipt_digest: digest('0'),
    };
    validation.receipt_digest = compute_validation_receipt_digest(&validation).expect("digest");
    let mut compilation = CompilationReceipt {
        receipt_id: id("compilation:owp-boot"),
        candidate_ref: candidate.clone(),
        candidate_source_digest: source.clone(),
        validation_receipt_ref: validation.receipt_id.clone(),
        compiler_ref: id("compiler:owp-boot"),
        ir_ref: Some(id("ir:owp-boot")),
        ir_digest: Some(digest('b')),
        disposition: PhaseDisposition::Passed,
        cost_estimate: BTreeMap::from([("instructions".to_owned(), 6)]),
        evidence: evidence("evidence:owp-compilation"),
        receipt_digest: digest('0'),
    };
    compilation.receipt_digest = compute_compilation_receipt_digest(&compilation).expect("digest");
    let mut verification = VerificationReceipt {
        receipt_id: id("verification:owp-boot"),
        candidate_ref: candidate.clone(),
        candidate_source_digest: source.clone(),
        compilation_receipt_ref: compilation.receipt_id.clone(),
        verifier_ref: id("verifier:owp-boot"),
        compiler_ref: compilation.compiler_ref.clone(),
        ir_ref: compilation.ir_ref.clone().expect("IR"),
        ir_digest: compilation.ir_digest.clone().expect("IR digest"),
        compiled_procedure_ref: id("procedure:owp-boot"),
        compiled_procedure_digest: digest('c'),
        anchor_set_digest: digest('d'),
        effect_declaration_digest: digest('e'),
        bound_set_ref: id("bounds:owp-boot"),
        bounds_digest: digest('f'),
        disposition: PhaseDisposition::Passed,
        evidence: evidence("evidence:owp-verification"),
        receipt_digest: digest('0'),
    };
    verification.receipt_digest =
        compute_verification_receipt_digest(&verification).expect("digest");
    let mut admission = AdmissionDisposition {
        disposition_id: id("admission:owp-boot"),
        candidate_ref: candidate.clone(),
        candidate_source_digest: source.clone(),
        validation_receipt_ref: validation.receipt_id.clone(),
        compilation_receipt_ref: compilation.receipt_id.clone(),
        verification_receipt_ref: verification.receipt_id.clone(),
        observer_ref: id("observer:owp-boot"),
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
        policy_ref: id("policy:owp-boot"),
        policy_digest: digest('1'),
        evidence: evidence("evidence:owp-admission"),
        disposition_digest: digest('0'),
    };
    admission.disposition_digest =
        compute_admission_disposition_digest(&admission).expect("digest");
    let boot_sop = SopRevisionAdmissionBinding {
        canonical_sop_ref: id("canonical-sop:owp"),
        sop_revision_ref: id("sop-revision:owp"),
        sop_revision_digest: source,
        satisfaction_signature_ref: id("signature:owp"),
        satisfaction_signature_digest: digest('2'),
        procedure_candidate_ref: candidate,
        validation,
        compilation,
        verification,
        admission,
    };
    let request = SopBootSessionRequest {
        profile: SOP_BOOT_SESSION_REQUEST_PROFILE.to_owned(),
        boot_request_id: id("boot-request:owp"),
        proposed_session_id: id("session:owp"),
        outer_host_id: id("outer-host:owp"),
        outer_host_identity_envelope_digest: digest('3'),
        boot_sop,
        objective_ref: id("objective:owp"),
        objective_digest: digest('4'),
        authority_ref: id("authority:sbs-owp"),
        authority_digest: digest('5'),
        bounds: SopBootSessionBounds {
            maximum_work_packets: 1,
            maximum_checkpoints: 64,
            maximum_update_proposals: 32,
            session_timeout_seconds: 86_400,
        },
        evidence_refs: [id("evidence:owp-boot")].into_iter().collect(),
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
    };
    compile_sop_boot_session(&request).expect("boot proposal")
}

fn capabilities(values: &[WorkCapability]) -> BTreeSet<WorkCapability> {
    values.iter().copied().collect()
}

pub(crate) fn fixture_request() -> ObjectiveWorkPlanRequest {
    use WorkCapability::*;
    let boot = boot_proposal();
    let classes = [
        (WorkStepClass::Inspect, capabilities(&[WorkspaceRead])),
        (WorkStepClass::Analyze, capabilities(&[])),
        (
            WorkStepClass::ProposeUpdate,
            capabilities(&[WorkspaceRead, WorkspaceMutation]),
        ),
        (
            WorkStepClass::Verify,
            capabilities(&[WorkspaceRead, TestExecution]),
        ),
        (
            WorkStepClass::ProposePublication,
            capabilities(&[Commit, Push]),
        ),
        (
            WorkStepClass::ProposeSucceedingSop,
            capabilities(&[WorkspaceRead, WorkspaceMutation]),
        ),
    ];
    let mut prior = None;
    let steps = classes
        .into_iter()
        .enumerate()
        .map(|(index, (class, requested_capabilities))| {
            let step_id = id(&format!("work-step:{}", index + 1));
            let dependency_refs = prior.clone().into_iter().collect();
            prior = Some(step_id.clone());
            WorkPlanStep {
                step_id,
                ordinal: index as u32 + 1,
                label: format!("bounded step {}", index + 1),
                class,
                dependency_refs,
                requested_capabilities,
                evidence_refs: [id(&format!("evidence:work-step:{}", index + 1))]
                    .into_iter()
                    .collect(),
            }
        })
        .collect();
    ObjectiveWorkPlanRequest {
        profile: OBJECTIVE_WORK_PLAN_REQUEST_PROFILE.to_owned(),
        objective_ref: boot.request.objective_ref.clone(),
        objective_digest: boot.request.objective_digest.clone(),
        boot_proposal: boot,
        plan: ObjectiveWorkPlanDraft {
            plan_id: id("work-plan:owp"),
            plan_revision_digest: digest('6'),
            steps,
        },
        authority_ref: id("authority:owp"),
        authority_digest: digest('7'),
        evidence_refs: [id("evidence:owp-request")].into_iter().collect(),
        unresolved_account: [
            "capabilities_not_granted",
            "succeeding_sop_not_authored",
            "updates_not_applied",
            "work_not_started",
            "workspace_not_admitted",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        non_authority: OBJECTIVE_WORK_PLAN_NON_AUTHORITY.to_owned(),
    }
}

#[test]
fn valid_plan_proposal_replays_and_round_trips() {
    let request = fixture_request();
    let proposal = compile_objective_work_plan(&request).expect("proposal");
    assert_eq!(
        proposal.lifecycle,
        ObjectiveWorkPlanLifecycle::AdmittedPlanNotExecuting
    );
    assert_eq!(proposal.authority, ObjectiveWorkPlanAuthority::PlanningOnly);
    assert_eq!(proposal.capability_account.len(), 8);
    assert_eq!(proposal.capability_denials.len(), 8);
    assert!(
        !proposal
            .requested_capability_union
            .contains(&WorkCapability::ProviderCall)
    );
    assert_eq!(
        proposal,
        compile_objective_work_plan(&request).expect("replay")
    );
    let request_form = to_objective_work_plan_request_machine_form(&request).expect("form");
    assert_eq!(
        request,
        from_objective_work_plan_request_machine_form(&request_form).expect("round trip")
    );
    let proposal_form = to_objective_work_plan_proposal_machine_form(&proposal).expect("form");
    assert_eq!(
        proposal,
        from_objective_work_plan_proposal_machine_form(&proposal_form).expect("round trip")
    );
}

#[test]
fn unknown_fields_refuse() {
    let mut value = serde_json::to_value(fixture_request()).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .insert("execute".to_owned(), json!(true));
    assert_eq!(
        from_objective_work_plan_request_machine_form(&value.to_string())
            .expect_err("unknown")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidMachineForm
    );
}

#[test]
fn boot_proposal_tampering_refuses() {
    let mut request = fixture_request();
    request.boot_proposal.proposal_digest = digest('8');
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("boot tamper")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidBootProposal
    );
}

#[test]
fn objective_substitution_refuses() {
    let mut request = fixture_request();
    request.objective_digest = digest('8');
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("objective")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidCorrespondence
    );

    let mut request = fixture_request();
    request.objective_ref = id("objective:substituted");
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("objective identity")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidCorrespondence
    );
}

#[test]
fn empty_and_oversized_plans_refuse() {
    let mut request = fixture_request();
    request.plan.steps.clear();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("empty")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidPlan
    );
    let mut request = fixture_request();
    let last = request.plan.steps.last().expect("step").clone();
    while request.plan.steps.len() < 65 {
        let mut step = last.clone();
        step.ordinal = request.plan.steps.len() as u32 + 1;
        step.step_id = id(&format!("work-step:{}", step.ordinal));
        step.dependency_refs = [request.plan.steps.last().expect("prior").step_id.clone()]
            .into_iter()
            .collect();
        request.plan.steps.push(step);
    }
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("oversized")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidPlan
    );
}

#[test]
fn step_identity_ordinal_and_label_substitutions_refuse() {
    let mut request = fixture_request();
    request.plan.steps[1].step_id = request.plan.steps[0].step_id.clone();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("collision")
            .code,
        ObjectiveWorkPlanFaultCode::IdentityCollision
    );
    let mut request = fixture_request();
    request.plan.steps[1].ordinal = 9;
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("ordinal")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidStep
    );
    let mut request = fixture_request();
    request.plan.steps[1].label = " ".to_owned();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("label")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidStep
    );

    let mut request = fixture_request();
    request.plan.steps[0].step_id = request.plan.plan_id.clone();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("reserved identity collision")
            .code,
        ObjectiveWorkPlanFaultCode::IdentityCollision
    );
}

#[test]
fn first_missing_and_forward_dependencies_refuse() {
    let mut request = fixture_request();
    request.plan.steps[0]
        .dependency_refs
        .insert(id("work-step:6"));
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("first dep")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidDependency
    );
    let mut request = fixture_request();
    request.plan.steps[1].dependency_refs.clear();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("missing dep")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidDependency
    );
    let mut request = fixture_request();
    request.plan.steps[1].dependency_refs = [request.plan.steps[5].step_id.clone()]
        .into_iter()
        .collect();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("forward dep")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidDependency
    );
}

#[test]
fn exact_step_capabilities_refuse_grant_laundering() {
    let mut request = fixture_request();
    request.plan.steps[1]
        .requested_capabilities
        .insert(WorkCapability::ProviderCall);
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("capability")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidCapability
    );
    let mut request = fixture_request();
    request.plan.steps[2]
        .requested_capabilities
        .remove(&WorkCapability::WorkspaceMutation);
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("missing capability")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidCapability
    );
}

#[test]
fn evidence_unresolved_nonauthority_and_digest_refuse() {
    let mut request = fixture_request();
    request.plan.steps[0].evidence_refs.clear();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("step evidence")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidEvidence
    );
    let mut request = fixture_request();
    request.unresolved_account.remove("work_not_started");
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("unresolved")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidUnresolvedAccount
    );
    let mut request = fixture_request();
    request.non_authority.push_str(" Granted.");
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("authority")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidAuthority
    );
    let mut request = fixture_request();
    request.authority_digest.value = "A".repeat(64);
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("digest")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidDigest
    );
}

#[test]
fn request_evidence_bounds_refuse() {
    let mut request = fixture_request();
    request.evidence_refs.clear();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("empty request evidence")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidEvidence
    );

    let mut request = fixture_request();
    request.evidence_refs = (0..33)
        .map(|index| id(&format!("evidence:owp-request:{index}")))
        .collect();
    assert_eq!(
        validate_objective_work_plan_request(&request)
            .expect_err("oversized request evidence")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidEvidence
    );
}

#[test]
fn output_union_account_and_denial_tampering_refuse() {
    let request = fixture_request();
    let mut proposal = compile_objective_work_plan(&request).expect("proposal");
    proposal
        .requested_capability_union
        .insert(WorkCapability::ProviderCall);
    assert_eq!(
        validate_objective_work_plan_proposal(&request, &proposal)
            .expect_err("union")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidCapability
    );
    let mut proposal = compile_objective_work_plan(&request).expect("proposal");
    proposal.capability_account.remove(&WorkCapability::Push);
    assert_eq!(
        validate_objective_work_plan_proposal(&request, &proposal)
            .expect_err("account")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidAuthority
    );
    let mut proposal = compile_objective_work_plan(&request).expect("proposal");
    proposal
        .capability_denials
        .remove(&WorkCapability::WorkspaceMutation);
    assert_eq!(
        validate_objective_work_plan_proposal(&request, &proposal)
            .expect_err("denial")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidAuthority
    );
}

#[test]
fn output_request_and_digests_refuse() {
    let request = fixture_request();
    let mut proposal = compile_objective_work_plan(&request).expect("proposal");
    proposal.request.plan.plan_revision_digest = digest('8');
    assert_eq!(
        validate_objective_work_plan_proposal(&request, &proposal)
            .expect_err("request")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidCorrespondence
    );
    let mut proposal = compile_objective_work_plan(&request).expect("proposal");
    proposal.request_digest = digest('8');
    assert_eq!(
        validate_objective_work_plan_proposal(&request, &proposal)
            .expect_err("request digest")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidDigest
    );
    let mut proposal = compile_objective_work_plan(&request).expect("proposal");
    proposal.proposal_digest = digest('8');
    assert_eq!(
        validate_objective_work_plan_proposal(&request, &proposal)
            .expect_err("proposal digest")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidDigest
    );
}

#[test]
fn widened_lifecycle_and_trailing_content_refuse() {
    let request = fixture_request();
    let proposal = compile_objective_work_plan(&request).expect("proposal");
    let mut value = serde_json::to_value(proposal).expect("value");
    value["lifecycle"] = json!("executing");
    assert_eq!(
        from_objective_work_plan_proposal_machine_form(&value.to_string())
            .expect_err("lifecycle")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidMachineForm
    );
    let form = to_objective_work_plan_request_machine_form(&request).expect("form");
    assert_eq!(
        from_objective_work_plan_request_machine_form(&format!("{form} true"))
            .expect_err("trailing")
            .code,
        ObjectiveWorkPlanFaultCode::InvalidMachineForm
    );
}
