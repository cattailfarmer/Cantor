use cantor_core::{
    Evox2ScratchBuildControllerPlan, Evox2ScratchBuildControllerRequest,
    Evox2ScratchBuildEffectProgram, Evox2ScratchBuildRemotePreflightProducerPlan,
};
use cantor_ecosystem::{
    Evox2RemotePreflightActivationEffectAccount, Evox2RemotePreflightActivationFaultCode,
    Evox2RemotePreflightActivationProposal, Evox2RemotePreflightOperatorDecision,
    Evox2RemotePreflightOperatorDecisionKind, activation_proposal_digest,
    canonical_evox2_remote_preflight_activation_request,
    compile_evox2_remote_preflight_activation_proposal,
    evox2_remote_preflight_operator_decision_signing_bytes,
    from_evox2_remote_preflight_activation_proposal_machine_form,
    from_evox2_remote_preflight_activation_proposal_verification_machine_form,
    from_evox2_remote_preflight_activation_request_machine_form,
    seal_evox2_remote_preflight_operator_decision_digest,
    to_evox2_remote_preflight_activation_proposal_machine_form,
    to_evox2_remote_preflight_activation_proposal_verification_machine_form,
    to_evox2_remote_preflight_activation_request_machine_form,
    to_evox2_remote_preflight_decision_correspondence_machine_form,
    to_evox2_remote_preflight_operator_decision_machine_form,
    verify_evox2_remote_preflight_activation_proposal,
    verify_evox2_remote_preflight_operator_decision_correspondence,
};
use ed25519_dalek::{Signer, SigningKey};

const REQUEST: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/controller_fixture/request.json"
);
const PLAN: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/controller_fixture/plan.json"
);
const PROGRAM: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/program.json"
);
const PRODUCER_PLAN: &str = include_str!(
    "../../../experiments/evox2_scratch_build_executor_p0/preflight_producer_fixture/producer_plan.json"
);

struct Fixture {
    request: Evox2ScratchBuildControllerRequest,
    plan: Evox2ScratchBuildControllerPlan,
    program: Evox2ScratchBuildEffectProgram,
    producer_plan: Evox2ScratchBuildRemotePreflightProducerPlan,
}

fn upstream() -> Fixture {
    Fixture {
        request: serde_json::from_str(REQUEST).unwrap(),
        plan: serde_json::from_str(PLAN).unwrap(),
        program: serde_json::from_str(PROGRAM).unwrap(),
        producer_plan: serde_json::from_str(PRODUCER_PLAN).unwrap(),
    }
}

fn proposal() -> Evox2RemotePreflightActivationProposal {
    let fixture = upstream();
    compile_evox2_remote_preflight_activation_proposal(
        &canonical_evox2_remote_preflight_activation_request().unwrap(),
        &fixture.request,
        &fixture.plan,
        &fixture.program,
        &fixture.producer_plan,
    )
    .unwrap()
}

fn signed_decision(
    proposal: &Evox2RemotePreflightActivationProposal,
    decision_kind: Evox2RemotePreflightOperatorDecisionKind,
) -> Evox2RemotePreflightOperatorDecision {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let mut decision = Evox2RemotePreflightOperatorDecision {
        profile: "cantor-evox2-remote-preflight-operator-decision/0.1".to_owned(),
        decision_uuid: "f0a48af4-ea98-45ff-8d00-4cae65fc1606".to_owned(),
        ceremony_uuid: proposal.ceremony_uuid.clone(),
        proposal_sha256: proposal.proposal_sha256.clone(),
        operator_principal: proposal.operator_principal.clone(),
        operator_role: proposal.operator_role.clone(),
        subject: proposal.subject.clone(),
        decision_nonce: proposal.decision_nonce.clone(),
        decision: decision_kind,
        issued_at_ms: proposal.decision_not_before_ms + 1,
        not_before_ms: proposal.decision_not_before_ms,
        expires_at_ms: proposal.decision_expires_at_ms,
        maximum_attempts: 1,
        maximum_permits: 1,
        maximum_processes: 1,
        retry_count: 0,
        verifying_key_hex: hex(&signing_key.verifying_key().to_bytes()),
        signature_hex: String::new(),
        fixture_only: proposal.fixture_only,
        decision_sha256: String::new(),
    };
    let signature = signing_key
        .sign(&evox2_remote_preflight_operator_decision_signing_bytes(&decision).unwrap());
    decision.signature_hex = hex(&signature.to_bytes());
    seal_evox2_remote_preflight_operator_decision_digest(decision).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn proposal_compiles_deterministically_with_zero_authority() {
    let fixture = upstream();
    let request = canonical_evox2_remote_preflight_activation_request().unwrap();
    let first = compile_evox2_remote_preflight_activation_proposal(
        &request,
        &fixture.request,
        &fixture.plan,
        &fixture.program,
        &fixture.producer_plan,
    )
    .unwrap();
    let second = compile_evox2_remote_preflight_activation_proposal(
        &request,
        &fixture.request,
        &fixture.plan,
        &fixture.program,
        &fixture.producer_plan,
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.roles.len(), 8);
    assert_eq!(first.stages.len(), 8);
    assert_eq!(first.argument_atoms.len(), 19);
    assert!(!first.live_authorization_admitted);
    assert!(!first.permit_mint_authorized);
    assert!(!first.runner_invocation_authorized);
    assert_eq!(first.effect_account, Default::default());
    verify_evox2_remote_preflight_activation_proposal(
        &request,
        &fixture.request,
        &fixture.plan,
        &fixture.program,
        &fixture.producer_plan,
        &first,
    )
    .unwrap();
}

#[test]
fn request_and_proposal_machine_forms_are_exact() {
    let request = canonical_evox2_remote_preflight_activation_request().unwrap();
    let request_form = to_evox2_remote_preflight_activation_request_machine_form(&request).unwrap();
    assert_eq!(
        from_evox2_remote_preflight_activation_request_machine_form(&request_form).unwrap(),
        request
    );
    let proposal = proposal();
    let proposal_form =
        to_evox2_remote_preflight_activation_proposal_machine_form(&proposal).unwrap();
    assert_eq!(
        from_evox2_remote_preflight_activation_proposal_machine_form(&proposal_form).unwrap(),
        proposal
    );
    let fixture = upstream();
    let verification = verify_evox2_remote_preflight_activation_proposal(
        &request,
        &fixture.request,
        &fixture.plan,
        &fixture.program,
        &fixture.producer_plan,
        &proposal,
    )
    .unwrap();
    let verification_form =
        to_evox2_remote_preflight_activation_proposal_verification_machine_form(&verification)
            .unwrap();
    assert_eq!(
        from_evox2_remote_preflight_activation_proposal_verification_machine_form(
            &verification_form
        )
        .unwrap(),
        verification
    );
}

#[test]
fn duplicate_and_noncanonical_machine_forms_refuse() {
    let request = canonical_evox2_remote_preflight_activation_request().unwrap();
    let form = to_evox2_remote_preflight_activation_request_machine_form(&request).unwrap();
    let duplicated = form.replacen("{\"profile\":", "{\"profile\":\"wrong\",\"profile\":", 1);
    assert!(from_evox2_remote_preflight_activation_request_machine_form(&duplicated).is_err());
    assert!(
        from_evox2_remote_preflight_activation_request_machine_form(&format!("{form}\n")).is_err()
    );
}

#[test]
fn proposal_semantic_and_lineage_mutations_refuse_after_redigest() {
    let fixture = upstream();
    let request = canonical_evox2_remote_preflight_activation_request().unwrap();
    for mutate in [
        |value: &mut Evox2RemotePreflightActivationProposal| value.retry_count = 1,
        |value: &mut Evox2RemotePreflightActivationProposal| value.maximum_permits = 2,
        |value: &mut Evox2RemotePreflightActivationProposal| {
            value.runner_bookend_commit = "0".repeat(40)
        },
        |value: &mut Evox2RemotePreflightActivationProposal| {
            value.live_authorization_admitted = true
        },
    ] {
        let mut changed = proposal();
        mutate(&mut changed);
        changed.proposal_sha256 = activation_proposal_digest(&changed).unwrap();
        assert!(
            verify_evox2_remote_preflight_activation_proposal(
                &request,
                &fixture.request,
                &fixture.plan,
                &fixture.program,
                &fixture.producer_plan,
                &changed,
            )
            .is_err()
        );
    }
}

#[test]
fn signed_authorize_decision_yields_correspondence_not_authority() {
    let proposal = proposal();
    let decision = signed_decision(
        &proposal,
        Evox2RemotePreflightOperatorDecisionKind::Authorize,
    );
    let correspondence = verify_evox2_remote_preflight_operator_decision_correspondence(
        &proposal,
        &decision,
        proposal.decision_not_before_ms + 2,
    )
    .unwrap();
    assert!(correspondence.signature_correspondence);
    assert!(correspondence.within_supplied_interval);
    assert!(correspondence.exact_scope);
    assert!(!correspondence.live_authorization_admitted);
    assert!(!correspondence.permit_mint_authorized);
    assert!(!correspondence.runner_invocation_authorized);
    assert_eq!(
        correspondence.effect_account,
        Evox2RemotePreflightActivationEffectAccount::default()
    );
    to_evox2_remote_preflight_decision_correspondence_machine_form(&correspondence).unwrap();
}

#[test]
fn signed_reject_remains_distinct_and_nonauthorizing() {
    let proposal = proposal();
    let decision = signed_decision(&proposal, Evox2RemotePreflightOperatorDecisionKind::Reject);
    let correspondence = verify_evox2_remote_preflight_operator_decision_correspondence(
        &proposal,
        &decision,
        proposal.decision_not_before_ms + 2,
    )
    .unwrap();
    assert_eq!(
        correspondence.decision,
        Evox2RemotePreflightOperatorDecisionKind::Reject
    );
    assert!(!correspondence.permit_mint_authorized);
}

#[test]
fn stale_future_and_scope_mismatched_decisions_refuse() {
    let proposal = proposal();
    let decision = signed_decision(
        &proposal,
        Evox2RemotePreflightOperatorDecisionKind::Authorize,
    );
    assert_eq!(
        verify_evox2_remote_preflight_operator_decision_correspondence(
            &proposal,
            &decision,
            proposal.decision_not_before_ms - 1,
        )
        .unwrap_err()
        .code,
        Evox2RemotePreflightActivationFaultCode::Time
    );
    assert_eq!(
        verify_evox2_remote_preflight_operator_decision_correspondence(
            &proposal,
            &decision,
            proposal.decision_expires_at_ms + 1,
        )
        .unwrap_err()
        .code,
        Evox2RemotePreflightActivationFaultCode::Time
    );
    let mut changed = decision;
    changed.maximum_processes = 2;
    changed = seal_evox2_remote_preflight_operator_decision_digest(changed).unwrap();
    assert_eq!(
        verify_evox2_remote_preflight_operator_decision_correspondence(
            &proposal,
            &changed,
            proposal.decision_not_before_ms + 2,
        )
        .unwrap_err()
        .code,
        Evox2RemotePreflightActivationFaultCode::Decision
    );
}

#[test]
fn signature_and_proposal_substitution_refuse() {
    let proposal = proposal();
    let mut signature_tamper = signed_decision(
        &proposal,
        Evox2RemotePreflightOperatorDecisionKind::Authorize,
    );
    signature_tamper.signature_hex.replace_range(0..2, "00");
    signature_tamper =
        seal_evox2_remote_preflight_operator_decision_digest(signature_tamper).unwrap();
    assert_eq!(
        verify_evox2_remote_preflight_operator_decision_correspondence(
            &proposal,
            &signature_tamper,
            proposal.decision_not_before_ms + 2,
        )
        .unwrap_err()
        .code,
        Evox2RemotePreflightActivationFaultCode::Signature
    );

    let mut substituted = signed_decision(
        &proposal,
        Evox2RemotePreflightOperatorDecisionKind::Authorize,
    );
    substituted.proposal_sha256 = "0".repeat(64);
    substituted = seal_evox2_remote_preflight_operator_decision_digest(substituted).unwrap();
    assert_eq!(
        verify_evox2_remote_preflight_operator_decision_correspondence(
            &proposal,
            &substituted,
            proposal.decision_not_before_ms + 2,
        )
        .unwrap_err()
        .code,
        Evox2RemotePreflightActivationFaultCode::Decision
    );
}

#[test]
fn decision_machine_form_refuses_raw_tamper() {
    let proposal = proposal();
    let decision = signed_decision(
        &proposal,
        Evox2RemotePreflightOperatorDecisionKind::Authorize,
    );
    let form = to_evox2_remote_preflight_operator_decision_machine_form(&decision).unwrap();
    assert!(!form.ends_with('\n'));
    assert!(
        cantor_ecosystem::from_evox2_remote_preflight_operator_decision_machine_form(&format!(
            "{form}\n"
        ))
        .is_err()
    );
}

#[test]
fn production_source_has_no_effect_or_permit_surface() {
    let source = include_str!("../src/evox2_remote_preflight_one_shot_activation_ceremony.rs");
    for forbidden in [
        "std::fs",
        "std::process",
        "Command::",
        "WindowsRemotePreflightBackend",
        "Evox2ScratchBuildRemotePreflightSingleUsePermit",
        "run_evox2_scratch_build_remote_preflight_once",
        "SigningKey",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}
