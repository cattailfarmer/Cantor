#[path = "self_work_lifecycle.rs"]
mod lifecycle_fixture;

use std::{
    collections::BTreeSet,
    io::Write,
    process::{Command, Stdio},
};

use cantor_core::*;
use lifecycle_fixture::{lifecycle_request, transition};
use serde_json::Value;

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

pub(crate) fn ready_request() -> SucceedingSopRequest {
    let lifecycle_request = lifecycle_request();
    let mut checkpoint = compile_self_work_lifecycle(&lifecycle_request)
        .expect("lifecycle")
        .checkpoint;
    for step in &lifecycle_request.work_plan_proposal.request.plan.steps[..5] {
        for (kind, successor) in [
            (
                SelfWorkTransitionKind::Start,
                SelfWorkLifecycleState::Active,
            ),
            (
                SelfWorkTransitionKind::SubmitForReview,
                SelfWorkLifecycleState::AwaitingReview,
            ),
            (
                SelfWorkTransitionKind::AcceptReview,
                SelfWorkLifecycleState::Complete,
            ),
        ] {
            let next = transition(&checkpoint, &step.step_id, kind, successor);
            checkpoint = advance_self_work_lifecycle(&lifecycle_request, &checkpoint, &next)
                .expect("advance");
        }
    }
    let selected = &lifecycle_request.work_plan_proposal.request.plan.steps[5];
    let selected_step_ref = selected.step_id.clone();
    let selected_attempt_ref = checkpoint.step_states[&selected_step_ref]
        .attempt_ref
        .clone();
    assert_eq!(
        checkpoint.step_states[&selected_step_ref].state,
        SelfWorkLifecycleState::ReadyAwaitingAdmission
    );

    let mut work_evidence_refs = lifecycle_request.evidence_refs.clone();
    work_evidence_refs.extend(selected.evidence_refs.iter().cloned());
    for dependency in &selected.dependency_refs {
        let dependency_step = lifecycle_request
            .work_plan_proposal
            .request
            .plan
            .steps
            .iter()
            .find(|step| step.step_id == *dependency)
            .expect("dependency step");
        work_evidence_refs.extend(dependency_step.evidence_refs.iter().cloned());
        for item in checkpoint
            .transitions
            .iter()
            .filter(|item| item.step_ref == *dependency)
        {
            work_evidence_refs.extend(item.evidence_refs.iter().cloned());
        }
    }

    SucceedingSopRequest {
        profile: SUCCEEDING_SOP_REQUEST_PROFILE.to_owned(),
        proposal_id: id("succeeding-sop-proposal:fixture"),
        lifecycle_request,
        lifecycle_checkpoint: checkpoint,
        selected_step_ref,
        selected_attempt_ref,
        author_ref: id("cantor-agent:fixture"),
        authorship_evidence_refs: [id("evidence:cantor-authorship")].into_iter().collect(),
        source_subject: "Cantor Fixture Succeeding SOP".to_owned(),
        source_text: "Subject: Cantor Fixture Succeeding SOP\n\n& [Purpose]\n  + continue the exact verified frontier\n".to_owned(),
        work_evidence_refs,
        unresolved_frontier: [
            "independent semantic review remains pending",
            "satisfaction signature and activation remain separate",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        review_obligations: SUCCEEDING_SOP_REVIEW_OBLIGATIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        non_authority: SUCCEEDING_SOP_NON_AUTHORITY.to_owned(),
    }
}

#[test]
fn proposal_and_receipt_are_deterministic_self_contained_and_strict() {
    let request = ready_request();
    let proposal = compile_succeeding_sop(&request).expect("proposal");
    let receipt = verify_succeeding_sop_proposal(&proposal).expect("receipt");
    assert_eq!(
        proposal.disposition,
        SucceedingSopDisposition::ProposedAwaitingIndependentReview
    );
    assert_eq!(
        proposal.authority,
        SucceedingSopAuthority::AuthorshipProposalOnly
    );
    assert_eq!(
        proposal.source_sha256,
        sha256_bytes(request.source_text.as_bytes())
    );
    assert_eq!(receipt.proposal, proposal);
    assert!(receipt.verified);
    assert_eq!(receipt.verified_checks.len(), 14);
    assert_eq!(
        receipt.authority,
        SucceedingSopVerificationAuthority::MachineCorrespondenceOnly
    );
    assert_eq!(
        receipt,
        verify_succeeding_sop_proposal(&compile_succeeding_sop(&request).expect("replay"))
            .expect("replay receipt")
    );

    let request_form = to_succeeding_sop_request_machine_form(&request).expect("request form");
    assert_eq!(
        request,
        from_succeeding_sop_request_machine_form(&request_form).expect("request round trip")
    );
    let proposal_form = to_succeeding_sop_proposal_machine_form(&proposal).expect("proposal form");
    assert_eq!(
        proposal,
        from_succeeding_sop_proposal_machine_form(&proposal_form).expect("proposal round trip")
    );
    let receipt_form = to_succeeding_sop_verification_machine_form(&receipt).expect("receipt form");
    assert_eq!(
        receipt,
        from_succeeding_sop_verification_machine_form(&receipt_form).expect("receipt round trip")
    );
}

#[test]
fn step_state_attempt_and_evidence_substitutions_refuse() {
    let request = ready_request();

    let mut wrong_step = request.clone();
    wrong_step.selected_step_ref = wrong_step
        .lifecycle_request
        .work_plan_proposal
        .request
        .plan
        .steps[0]
        .step_id
        .clone();
    wrong_step.selected_attempt_ref = wrong_step.lifecycle_checkpoint.step_states
        [&wrong_step.selected_step_ref]
        .attempt_ref
        .clone();
    assert_eq!(
        compile_succeeding_sop(&wrong_step)
            .expect_err("wrong step")
            .code,
        SucceedingSopFaultCode::InvalidStep
    );

    let mut attempt = request.clone();
    attempt.selected_attempt_ref = id("self-work-attempt:substituted");
    assert_eq!(
        compile_succeeding_sop(&attempt).expect_err("attempt").code,
        SucceedingSopFaultCode::InvalidState
    );

    let mut missing = request.clone();
    let first = missing
        .work_evidence_refs
        .iter()
        .next()
        .cloned()
        .expect("evidence");
    missing.work_evidence_refs.remove(&first);
    assert_eq!(
        compile_succeeding_sop(&missing)
            .expect_err("missing evidence")
            .code,
        SucceedingSopFaultCode::InvalidEvidence
    );

    let mut extra = request;
    extra.work_evidence_refs.insert(id("evidence:unrelated"));
    assert_eq!(
        compile_succeeding_sop(&extra)
            .expect_err("extra evidence")
            .code,
        SucceedingSopFaultCode::InvalidEvidence
    );
}

#[test]
fn profile_dependency_and_authorship_evidence_bounds_refuse() {
    let request = ready_request();

    let mut profile = request.clone();
    profile.profile = "cantor-succeeding-sop-request/substituted".to_owned();
    assert_eq!(
        compile_succeeding_sop(&profile).expect_err("profile").code,
        SucceedingSopFaultCode::InvalidProfile
    );

    let mut incomplete = request.clone();
    incomplete.lifecycle_checkpoint = compile_self_work_lifecycle(&incomplete.lifecycle_request)
        .expect("initial lifecycle")
        .checkpoint;
    incomplete.selected_attempt_ref = incomplete.lifecycle_checkpoint.step_states
        [&incomplete.selected_step_ref]
        .attempt_ref
        .clone();
    let selected = incomplete
        .lifecycle_request
        .work_plan_proposal
        .request
        .plan
        .steps
        .iter()
        .find(|step| step.step_id == incomplete.selected_step_ref)
        .expect("selected step");
    assert!(selected.dependency_refs.iter().any(|dependency| {
        incomplete.lifecycle_checkpoint.step_states[dependency].state
            != SelfWorkLifecycleState::Complete
    }));
    assert_eq!(
        compile_succeeding_sop(&incomplete)
            .expect_err("incomplete dependency")
            .code,
        SucceedingSopFaultCode::InvalidState
    );

    let mut authorship = request;
    authorship.authorship_evidence_refs.clear();
    assert_eq!(
        compile_succeeding_sop(&authorship)
            .expect_err("authorship evidence")
            .code,
        SucceedingSopFaultCode::InvalidEvidence
    );
}

#[test]
fn source_author_frontier_obligation_and_authority_faults_refuse() {
    let request = ready_request();
    for source in [
        "Subject: bad\r\n",
        "Subject: bad\0\n",
        "Subject: missing terminal LF",
        "Subject: doubled terminal LF\n\n",
    ] {
        let mut candidate = request.clone();
        candidate.source_text = source.to_owned();
        assert_eq!(
            compile_succeeding_sop(&candidate).expect_err("source").code,
            SucceedingSopFaultCode::InvalidSource
        );
    }

    let mut subject = request.clone();
    subject.source_subject = " untrimmed".to_owned();
    assert_eq!(
        compile_succeeding_sop(&subject).expect_err("subject").code,
        SucceedingSopFaultCode::InvalidSource
    );

    let mut author = request.clone();
    author.author_ref = author.selected_step_ref.clone();
    assert_eq!(
        compile_succeeding_sop(&author)
            .expect_err("author collision")
            .code,
        SucceedingSopFaultCode::InvalidAuthor
    );

    let mut frontier = request.clone();
    frontier.unresolved_frontier = BTreeSet::new();
    assert_eq!(
        compile_succeeding_sop(&frontier)
            .expect_err("frontier")
            .code,
        SucceedingSopFaultCode::InvalidFrontier
    );

    let mut obligations = request.clone();
    obligations
        .review_obligations
        .remove("independently_review_semantics");
    assert_eq!(
        compile_succeeding_sop(&obligations)
            .expect_err("obligations")
            .code,
        SucceedingSopFaultCode::InvalidObligation
    );

    let mut authority = request;
    authority.non_authority.push_str(" widened");
    assert_eq!(
        compile_succeeding_sop(&authority)
            .expect_err("authority")
            .code,
        SucceedingSopFaultCode::InvalidAuthority
    );
}

#[test]
fn proposal_and_verification_tampering_refuse_atomically() {
    let request = ready_request();
    let proposal = compile_succeeding_sop(&request).expect("proposal");

    let mut source = proposal.clone();
    source.source_text = "Subject: substituted\n".to_owned();
    assert_eq!(
        validate_succeeding_sop_proposal(&request, &source)
            .expect_err("source projection")
            .code,
        SucceedingSopFaultCode::InvalidCorrespondence
    );

    let mut source_digest = proposal.clone();
    source_digest.source_sha256 = sha256_bytes(b"different raw source bytes\n");
    assert_eq!(
        validate_succeeding_sop_proposal(&request, &source_digest)
            .expect_err("raw source digest")
            .code,
        SucceedingSopFaultCode::InvalidDigest
    );

    let mut digest = proposal.clone();
    let replacement = if digest.proposal_digest.value.starts_with('f') {
        "e"
    } else {
        "f"
    };
    digest
        .proposal_digest
        .value
        .replace_range(0..1, replacement);
    assert_eq!(
        validate_succeeding_sop_proposal(&request, &digest)
            .expect_err("proposal digest")
            .code,
        SucceedingSopFaultCode::InvalidDigest
    );

    let mut receipt = verify_succeeding_sop_proposal(&proposal).expect("receipt");
    receipt.verified = false;
    assert_eq!(
        validate_succeeding_sop_verification_receipt(&receipt)
            .expect_err("verified bit")
            .code,
        SucceedingSopFaultCode::InvalidCorrespondence
    );

    let mut receipt = verify_succeeding_sop_proposal(&proposal).expect("receipt");
    let replacement = if receipt.verification_digest.value.starts_with('f') {
        "e"
    } else {
        "f"
    };
    receipt
        .verification_digest
        .value
        .replace_range(0..1, replacement);
    assert_eq!(
        validate_succeeding_sop_verification_receipt(&receipt)
            .expect_err("receipt digest")
            .code,
        SucceedingSopFaultCode::InvalidDigest
    );
}

#[test]
fn unknown_fields_and_oversized_machine_forms_refuse() {
    let request = ready_request();
    let mut value = serde_json::to_value(&request).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .insert("unexpected".to_owned(), Value::Bool(true));
    assert_eq!(
        from_succeeding_sop_request_machine_form(&serde_json::to_string(&value).expect("form"))
            .expect_err("unknown field")
            .code,
        SucceedingSopFaultCode::InvalidMachineForm
    );

    let oversized = "x".repeat(SUCCEEDING_SOP_MAX_MACHINE_FORM_BYTES + 1);
    assert_eq!(
        from_succeeding_sop_request_machine_form(&oversized)
            .expect_err("oversized")
            .code,
        SucceedingSopFaultCode::InvalidBound
    );
}

#[test]
fn cli_compiles_and_replays_receipt_without_output_path() {
    let request = ready_request();
    let request_form = to_succeeding_sop_request_machine_form(&request).expect("request form");
    let compile = invoke_cli("compile", &request_form, &[]);
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let receipt_form = String::from_utf8(compile.stdout).expect("stdout");
    let receipt = from_succeeding_sop_verification_machine_form(receipt_form.trim_end())
        .expect("compiled receipt");
    assert!(receipt.verified);

    let verify = invoke_cli("verify", receipt_form.trim_end(), &[]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(verify.stdout, receipt_form.as_bytes());

    let extra = invoke_cli("compile", &request_form, &["forbidden-output.json"]);
    assert!(!extra.status.success());
}

#[test]
fn production_surface_contains_no_physical_effect_route() {
    let module = include_str!("../src/succeeding_sop_proposal.rs");
    let cli = include_str!("../src/bin/cantor-succeeding-sop-proposal.rs");
    for forbidden in [
        "std::fs",
        "std::process::Command",
        "TcpStream",
        "UdpSocket",
        "unsafe {",
        "SystemTime",
        "std::env::var",
    ] {
        assert!(!module.contains(forbidden), "module contains {forbidden}");
        assert!(!cli.contains(forbidden), "CLI contains {forbidden}");
    }
    assert!(!cli.contains("create_dir"));
    assert!(!cli.contains("fs::write"));
}

fn invoke_cli(operation: &str, input: &str, extra_arguments: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cantor-succeeding-sop-proposal"))
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
