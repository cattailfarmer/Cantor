use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn base_candidate() -> ProcedureCandidate {
    serde_json::from_str(include_str!("fixtures/cppe_two_process_candidate.json"))
        .expect("checked two-process candidate fixture")
}

fn candidate(class: AuthorshipClass) -> ProcedureCandidate {
    let mut candidate = base_candidate();
    match class {
        AuthorshipClass::HandAuthored => {
            candidate.candidate_id = sid("authorship-candidate:hand");
            candidate.author_ref = sid("human:procedure-author");
            candidate.provenance_refs = BTreeSet::from([sid("evidence:hand-authorship")]);
        }
        AuthorshipClass::ModelShaped => {
            candidate.candidate_id = sid("authorship-candidate:model");
            candidate.author_ref = sid("model-output:procedure-author");
            candidate.provenance_refs = BTreeSet::from([sid("evidence:model-shaped-output")]);
        }
    }
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).expect("candidate source digest");
    candidate
}

fn template(class: AuthorshipClass) -> AuthorshipLaneTemplate {
    let lane = match class {
        AuthorshipClass::HandAuthored => "hand",
        AuthorshipClass::ModelShaped => "model",
    };
    let evidence = match class {
        AuthorshipClass::HandAuthored => sid("evidence:hand-authorship"),
        AuthorshipClass::ModelShaped => sid("evidence:model-shaped-output"),
    };
    AuthorshipLaneTemplate {
        class,
        authorship_evidence_refs: BTreeSet::from([evidence]),
        validator_ref: sid("validator:independent-authorship-fixture"),
        policy_ref: sid(&format!("policy:authorship-{lane}")),
        aliases: BTreeSet::from([format!("authorship-{lane}")]),
        permitted_invocation_context: "effectless-authorship-parity".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid(&format!("authorship-invocation:{lane}")),
        caller_ref: sid("caller:authorship-fixture"),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:authorship-fixture"),
        initial_logical_time: 10,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention"),
        session_generation_ref: sid(&format!("authorship-session-generation:{lane}")),
        session_ref: sid(&format!("authorship-session:{lane}")),
        session_purpose: "compare authorship lanes without authority inheritance".to_owned(),
        frame_ref: sid(&format!("authorship-frame:{lane}")),
        frame_conditions: BTreeSet::from(["effectless".to_owned()]),
        frame_constraints: BTreeSet::from(["same-pipeline".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    }
}

fn lane(class: AuthorshipClass) -> AuthorshipLaneEvidence {
    run_authorship_lane(&candidate(class), &template(class), &BTreeMap::new())
        .expect("authorship lane")
}

#[test]
fn hand_and_model_shaped_candidates_share_one_exact_pipeline_and_behavior() {
    let hand = lane(AuthorshipClass::HandAuthored);
    let model = lane(AuthorshipClass::ModelShaped);
    assert_ne!(hand.candidate.candidate_id, model.candidate.candidate_id);
    assert_ne!(hand.procedure.procedure_id, model.procedure.procedure_id);
    assert_eq!(hand.candidate.source_digest, model.candidate.source_digest);
    assert_eq!(
        hand.coordination.result.output,
        model.coordination.result.output
    );
    assert_eq!(
        hand.stable_session.status,
        NegotiationStatus::StableCandidate
    );
    assert_eq!(
        model.stable_session.status,
        NegotiationStatus::StableCandidate
    );

    let first = compare_authorship_lanes(&hand, &model).expect("parity report");
    let second = compare_authorship_lanes(&hand, &model).expect("repeat report");
    assert_eq!(first, second);
    assert_eq!(first.disposition, PhaseDisposition::Passed);
    assert!(first.axis_results.values().all(|value| *value));
    assert_eq!(first.hand_projection_digest, first.model_projection_digest);
    assert_eq!(
        compute_authorship_parity_report_digest(&first).expect("report digest"),
        first.report_digest
    );
}

#[test]
fn model_shaped_provenance_cannot_self_validate_or_impersonate_authority() {
    let candidate = candidate(AuthorshipClass::ModelShaped);
    let mut self_validating = template(AuthorshipClass::ModelShaped);
    self_validating.validator_ref = candidate.author_ref.clone();
    assert!(run_authorship_lane(&candidate, &self_validating, &BTreeMap::new()).is_err());

    let mut observer_impersonation = candidate.clone();
    observer_impersonation.author_ref = sid(CPPE_FAKE_OBSERVER_ID);
    assert!(
        run_authorship_lane(
            &observer_impersonation,
            &template(AuthorshipClass::ModelShaped),
            &BTreeMap::new(),
        )
        .is_err()
    );
}

#[test]
fn authorship_claim_without_exact_provenance_fails_before_validation() {
    let candidate = candidate(AuthorshipClass::ModelShaped);
    let mut template = template(AuthorshipClass::ModelShaped);
    template
        .authorship_evidence_refs
        .insert(sid("evidence:absent"));
    let fault = run_authorship_lane(&candidate, &template, &BTreeMap::new())
        .expect_err("missing provenance must fail");
    assert!(fault.message.contains("provenance"));
}

#[test]
fn semantic_drift_is_visible_even_when_both_lanes_individually_pass() {
    let hand = lane(AuthorshipClass::HandAuthored);
    let mut model_candidate = candidate(AuthorshipClass::ModelShaped);
    model_candidate.normalized_source_form = Some(ProcedureValue::List {
        members: vec![
            ProcedureValue::IdentityReference {
                value: sid("coord-process:b"),
            },
            ProcedureValue::IdentityReference {
                value: sid("coord-process:a"),
            },
        ],
    });
    model_candidate.source_digest =
        compute_candidate_source_digest(&model_candidate).expect("drift digest");
    let model = run_authorship_lane(
        &model_candidate,
        &template(AuthorshipClass::ModelShaped),
        &BTreeMap::new(),
    )
    .expect("individually valid drift lane");
    let report = compare_authorship_lanes(&hand, &model).expect("refusal report");
    assert_eq!(report.disposition, PhaseDisposition::Refused);
    assert_eq!(report.axis_results.get("semantic_source"), Some(&false));
    assert_ne!(
        report.hand_projection_digest,
        report.model_projection_digest
    );
}

#[test]
fn substituted_runtime_evidence_cannot_be_laundered_as_authorship_parity() {
    let hand = lane(AuthorshipClass::HandAuthored);
    let mut model = lane(AuthorshipClass::ModelShaped);
    model.coordination.result.consumed_budget.steps += 1;
    let fault = compare_authorship_lanes(&hand, &model)
        .expect_err("substituted evidence is invalid, not a parity lane");
    assert!(fault.message.contains("coordination evidence"));
}

#[test]
fn different_pipeline_principal_is_visible_even_with_equal_behavior() {
    let hand = lane(AuthorshipClass::HandAuthored);
    let model_candidate = candidate(AuthorshipClass::ModelShaped);
    let mut model_template = template(AuthorshipClass::ModelShaped);
    model_template.validator_ref = sid("validator:different-independent-fixture");
    let model = run_authorship_lane(&model_candidate, &model_template, &BTreeMap::new())
        .expect("valid alternate pipeline lane");
    let report = compare_authorship_lanes(&hand, &model).expect("refusal report");
    assert_eq!(report.disposition, PhaseDisposition::Refused);
    assert_eq!(report.axis_results.get("pipeline_principals"), Some(&false));
}

#[test]
fn textual_model_output_uses_the_same_compiler_refusal_boundary() {
    let mut candidate = candidate(AuthorshipClass::ModelShaped);
    candidate.source_text = Some("process Observer; begin end".to_owned());
    candidate.normalized_source_form = None;
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).expect("text source digest");
    let fault = run_authorship_lane(
        &candidate,
        &template(AuthorshipClass::ModelShaped),
        &BTreeMap::new(),
    )
    .expect_err("text parser authority remains absent");
    assert!(fault.message.contains("compilable normalized candidate"));
}
