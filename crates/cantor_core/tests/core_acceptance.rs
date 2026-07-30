use cantor_core::FixtureId;
use cantor_core::review::ReviewVerdict;
use cantor_core::review::no_match_history_review;
use cantor_core::{
    FaultKind, Instruction, SemanticState, StateStatus, content_digest, evaluate,
    from_machine_form, run_fixture, to_machine_form,
};

fn accepted(fixture: FixtureId) -> cantor_core::fixtures::FixtureReport {
    let report = run_fixture(fixture).expect("fixture execution must produce a report");
    assert!(report.is_accepted(), "{}", report.decision.reason);
    assert!(!report.transitions.is_empty());
    assert!(report.proof.iter().all(|proof| proof.passed));
    assert_eq!(report.review.verdict, ReviewVerdict::Accept);
    assert_eq!(report.before_state.ir_version, "cantor-ir/0.1");
    for transition in &report.transitions {
        assert!(!transition.trace.reason.is_empty());
        assert!(!transition.history_review.coverage_statement.is_empty());
        assert_eq!(
            transition.history_review.reconciliation,
            "no_pertinent_history; present input and purpose govern"
        );
    }
    report
}

#[test]
fn fixture_1_aliases_and_contextual_meanings() {
    let report = accepted(FixtureId::AliasesAndContext);
    assert_eq!(report.after_state.environment.units.len(), 2);
    assert_eq!(report.after_state.environment.labels["bank"].len(), 2);
    assert_eq!(
        report
            .after_state
            .environment
            .resolve_label_in_scope("bank", "finance")
            .len(),
        1
    );
}

#[test]
fn fixture_2_inspectable_inference_derivation() {
    let report = accepted(FixtureId::InspectableInference);
    assert_eq!(report.transitions[0].judgments[0].grounds.len(), 3);
    assert!(report.transitions[0].trace.reason.contains("named rule"));
}

#[test]
fn fixture_3_unknown_is_distinct_from_invalid() {
    let report = accepted(FixtureId::UnknownVersusInvalid);
    assert_eq!(report.faults.len(), 2);
    assert_eq!(report.faults[0].kind, FaultKind::UnknownKnowledge);
    assert_eq!(report.faults[1].kind, FaultKind::ConstraintViolation);
}

#[test]
fn fixture_4_pure_transformation_has_no_effect() {
    let report = accepted(FixtureId::PureTransformation);
    assert_eq!(report.after_state.values["sum"], 5);
    assert!(report.after_state.pending_effects.is_empty());
    assert!(report.transitions[0].effect_events.is_empty());
}

#[test]
fn fixture_5_effect_is_denied_or_authorized_but_never_committed() {
    let report = accepted(FixtureId::EffectAuthority);
    assert_eq!(report.faults[0].kind, FaultKind::UnauthorizedEffect);
    assert_eq!(report.after_state.pending_effects.len(), 1);
    assert_eq!(report.after_state.budget.effects_remaining, 1);
}

#[test]
fn fixture_6_yield_serializes_and_reenters_exactly() {
    let report = accepted(FixtureId::YieldAndReentry);
    let yielded = &report.transitions[0].after_state;
    assert_eq!(yielded.status, StateStatus::Yielded);
    let machine_form = to_machine_form(yielded).expect("yielded state must serialize");
    let restored = from_machine_form(&machine_form).expect("yielded state must restore");
    assert_eq!(*yielded, restored);
    assert_eq!(report.after_state.status, StateStatus::Ready);
    let mut unknown_field: serde_json::Value =
        serde_json::from_str(&machine_form).expect("state machine form must be JSON");
    unknown_field
        .as_object_mut()
        .expect("state machine form must be an object")
        .insert(
            "implicit_instruction".to_owned(),
            serde_json::Value::Bool(true),
        );
    assert!(
        from_machine_form::<SemanticState>(&unknown_field.to_string()).is_err(),
        "unknown state fields must fail closed rather than disappear"
    );

    let mut non_identical = yielded.clone();
    non_identical.purpose = "altered after yield".to_owned();
    let history = no_match_history_review("yield_and_reentry", 99, yielded, "CONTROL")
        .expect("negative reentry review must form");
    let rejected = evaluate(
        yielded,
        &Instruction::Reenter {
            restored_state: Box::new(non_identical),
        },
        history,
    )
    .expect("invalid reentry must emit a transition");
    assert_eq!(rejected.faults[0].kind, FaultKind::InvalidReentry);
    assert_eq!(rejected.after_state.status, StateStatus::Faulted);
}

#[test]
fn fixture_7_verbose_and_condensed_surfaces_have_equivalent_ir() {
    let report = accepted(FixtureId::SurfaceEquivalence);
    assert!(report.proof[0].claim.contains("equivalent semantic IR"));
    assert!(report.proof[0].passed);
}

#[test]
fn fixture_8_skos_import_declares_fidelity_and_lineage() {
    let report = accepted(FixtureId::OntologyImport);
    assert_eq!(report.after_state.environment.relations.len(), 1);
    assert!(report.transitions[2].faults.is_empty());
    let report_digest = content_digest(&report).expect("report must have content identity");
    assert_eq!(report_digest.algorithm, "fnv1a64-fixture-only");
}
