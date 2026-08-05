use cantor_core::{
    CalendarEvaluationKind, CalendarLifecycleState, RepositoryStatus, RuntimeEvaluation,
    RuntimeFaultKind, RuntimeOperation, RuntimeOutput, digest_repository_generation,
    evaluate_runtime,
};

#[allow(dead_code)]
mod temporal_runtime_support;

use temporal_runtime_support::{
    accepted, append_observation, calendar_revision, candidate_generation, context, id, ids,
    initial_runtime, initialize_repository,
};

#[test]
fn compare_and_append_cannot_launder_repository_admission_or_terminal_status() {
    for status in [
        RepositoryStatus::Admitted,
        RepositoryStatus::Superseded,
        RepositoryStatus::Revoked,
        RepositoryStatus::Quarantined,
        RepositoryStatus::Archived,
    ] {
        let runtime = initial_runtime();
        let mut generation = candidate_generation("generation.claimed", &[], &[], None);
        generation.status = status;
        generation.created_by_disposition_ref = if status == RepositoryStatus::Admitted {
            Some(id("observer.disposition.unverified"))
        } else {
            None
        };
        generation.root_digest =
            digest_repository_generation(&generation).expect("generation digest serializes");
        let operation = RuntimeOperation::CompareAndAppend {
            context: context(&runtime, &format!("audit.repository.status.{status:?}")),
            branch_ref: id("branch.main"),
            expected_generation_ref: None,
            generation,
            content: Vec::new(),
            events: Vec::new(),
            snapshot: None,
        };
        match evaluate_runtime(&runtime, &operation) {
            RuntimeEvaluation::Refused { fault } => {
                assert_eq!(fault.kind, RuntimeFaultKind::InvalidForm)
            }
            _ => panic!("compare-and-append must remain candidate-only"),
        }
    }
}

#[test]
fn branch_and_merge_candidates_preserve_exact_predecessor_evidence() {
    let runtime = append_observation(&initialize_repository(&initial_runtime()));
    let branch = RuntimeOperation::CompareAndAppend {
        context: context(&runtime, "audit.repository.branch"),
        branch_ref: id("branch.feature"),
        expected_generation_ref: Some(id("generation.one")),
        generation: candidate_generation("generation.feature", &["generation.one"], &[], None),
        content: Vec::new(),
        events: Vec::new(),
        snapshot: None,
    };
    let branched = accepted(evaluate_runtime(&runtime, &branch)).0;
    assert_eq!(
        branched.root.repository.branch_heads[&id("branch.feature")],
        id("generation.feature")
    );
    assert_eq!(
        branched.root.repository.branch_heads[&id("branch.main")],
        id("generation.two")
    );

    let merge = RuntimeOperation::CompareAndAppend {
        context: context(&branched, "audit.repository.merge"),
        branch_ref: id("branch.main"),
        expected_generation_ref: Some(id("generation.two")),
        generation: candidate_generation(
            "generation.merge",
            &["generation.two", "generation.feature"],
            &["event.observation"],
            None,
        ),
        content: Vec::new(),
        events: Vec::new(),
        snapshot: None,
    };
    let merged = accepted(evaluate_runtime(&branched, &merge)).0;
    assert_eq!(
        merged.root.forms.repository_generations[&id("generation.merge")]
            .predecessor_generation_refs,
        ids(&["generation.two", "generation.feature"])
    );
    assert_eq!(
        merged.root.repository.branch_heads[&id("branch.main")],
        id("generation.merge")
    );
    assert_eq!(
        merged.root.repository.index.source_generation_ref,
        Some(id("generation.merge"))
    );
}

#[test]
fn every_authorized_calendar_evaluation_kind_has_a_legal_fixture_transition() {
    let base = calendar_revision(&append_observation(&initialize_repository(
        &initial_runtime(),
    )));
    let advanced = accepted(evaluate_runtime(
        &base,
        &RuntimeOperation::AdvanceLogicalTime {
            context: context(&base, "audit.calendar.advance"),
            delta: 1,
        },
    ))
    .0;
    for (label, kind, state) in [
        (
            "due",
            CalendarEvaluationKind::Due,
            CalendarLifecycleState::Triggered,
        ),
        (
            "missed",
            CalendarEvaluationKind::Missed,
            CalendarLifecycleState::Missed,
        ),
        (
            "cancelled",
            CalendarEvaluationKind::Cancelled,
            CalendarLifecycleState::Cancelled,
        ),
        (
            "completed",
            CalendarEvaluationKind::Completed,
            CalendarLifecycleState::Completed,
        ),
        (
            "superseded",
            CalendarEvaluationKind::Superseded,
            CalendarLifecycleState::Superseded,
        ),
    ] {
        let mut successor = advanced.root.forms.calendar_items[&id("calendar.one.rev1")].clone();
        successor.revision_id = id(&format!("calendar.one.audit.{label}"));
        successor.predecessor_revision_ref = Some(id("calendar.one.rev1"));
        successor.lifecycle_state = state;
        let operation = RuntimeOperation::EvaluateCalendarState {
            context: context(&advanced, &format!("audit.calendar.{label}")),
            predecessor_revision_ref: id("calendar.one.rev1"),
            successor_item: successor,
            evaluated_at_tick: 1,
            evaluation_kind: kind,
            candidate_event_id: id(&format!("event.candidate.calendar.{label}")),
        };
        let receipt = accepted(evaluate_runtime(&advanced, &operation)).1;
        match receipt.output {
            RuntimeOutput::CalendarStateEvaluation { candidate, .. } => {
                assert_eq!(candidate.evaluation_kind, kind);
                assert_eq!(candidate.lifecycle_state, state);
            }
            other => panic!("calendar evaluation expected, observed {other:?}"),
        }
    }
}
