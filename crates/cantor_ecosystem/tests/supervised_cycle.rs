mod common;

use std::collections::BTreeSet;

use cantor_core::{ProtocolStatus, sha256_bytes};
use cantor_ecosystem::{
    CodexAdapter, CycleProgress, EcosystemFaultCode, MessageKind, MockCodexAdapter, ReviewCheck,
    ReviewCheckKind, ReviewDisposition,
};

use common::{candidate, id, protocol_request, run, standard_fixture};

#[test]
fn successful_cycle_has_exact_causal_transcript_and_no_effects() {
    let (commission, packet, candidate) = standard_fixture();
    let outcome = run(commission.clone(), packet.clone(), candidate).expect("successful cycle");

    assert_eq!(outcome.progress, CycleProgress::Accepted);
    assert_eq!(outcome.cantor_response.status, ProtocolStatus::Success);
    assert_eq!(
        outcome.final_decision.disposition,
        ReviewDisposition::Accept
    );
    assert_eq!(
        outcome.final_decision.accepted_candidate_uuid,
        Some(id("candidate:fixture"))
    );
    assert!(outcome.candidate.requested_effects.is_empty());
    assert_eq!(outcome.metrics.accepted_messages, 7);
    assert_eq!(outcome.metrics.codex_adapter_calls, 2);
    assert_eq!(outcome.metrics.cantor_adapter_calls, 1);
    assert_eq!(outcome.metrics.maximum_call_depth_observed, 2);

    let expected_kinds = [
        MessageKind::Commission,
        MessageKind::Assignment,
        MessageKind::CantorQuery,
        MessageKind::CantorReturn,
        MessageKind::Candidate,
        MessageKind::Review,
        MessageKind::Decision,
    ];
    assert_eq!(
        outcome
            .transcript
            .iter()
            .map(|message| message.message_kind)
            .collect::<Vec<_>>(),
        expected_kinds
    );
    assert_eq!(outcome.transcript[0].causation_uuid, None);
    for index in 1..outcome.transcript.len() {
        assert_eq!(
            outcome.transcript[index].causation_uuid.as_ref(),
            Some(&outcome.transcript[index - 1].message_uuid)
        );
        assert_eq!(
            outcome.transcript[index - 1].recipient,
            outcome.transcript[index].sender
        );
        assert_eq!(
            outcome.transcript[index].correlation_uuid,
            commission.commission_uuid
        );
        assert_eq!(outcome.transcript[index].frame_digest, packet.frame_digest);
    }
}

#[test]
fn repeated_cycle_is_structurally_and_byte_deterministic() {
    let first = {
        let (commission, packet, candidate) = standard_fixture();
        run(commission, packet, candidate).expect("first cycle")
    };
    let second = {
        let (commission, packet, candidate) = standard_fixture();
        run(commission, packet, candidate).expect("second cycle")
    };

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).expect("first JSON"),
        serde_json::to_vec(&second).expect("second JSON")
    );
    assert_eq!(
        cantor_core::sha256_digest(&first)
            .expect("canonical outcome digest")
            .value,
        "2ef72ed3edf4bf58e80e24c5d86bea18572ba10324e27e02aacc63569cd78b3c"
    );
}

#[test]
fn requested_effect_forces_revision_without_effect_authority() {
    let (commission, packet, mut candidate) = standard_fixture();
    candidate.requested_effects = ["git_push".to_owned()].into_iter().collect();

    let outcome = run(commission, packet, candidate).expect("bounded revision outcome");

    assert_eq!(outcome.progress, CycleProgress::Revise);
    assert_eq!(outcome.review.disposition, ReviewDisposition::Revise);
    assert_eq!(
        outcome.final_decision.disposition,
        ReviewDisposition::Revise
    );
    assert_eq!(outcome.final_decision.accepted_candidate_uuid, None);
    assert!(
        outcome.review.checks.iter().any(|check| !check.passed
            && check.check == cantor_ecosystem::ReviewCheckKind::EffectBoundary)
    );
}

#[test]
fn missing_acceptance_criterion_forces_revision() {
    let (commission, packet, mut candidate) = standard_fixture();
    candidate
        .satisfied_criterion_ids
        .remove(&id("criterion:no_effect"));

    let outcome = run(commission, packet, candidate).expect("bounded revision outcome");

    assert_eq!(outcome.progress, CycleProgress::Revise);
    assert!(outcome.review.checks.iter().any(|check| !check.passed
        && check.check == cantor_ecosystem::ReviewCheckKind::AcceptanceCriteria));
}

#[test]
fn missing_proof_obligation_forces_honesty_revision() {
    let (commission, packet, mut candidate) = standard_fixture();
    candidate.proof_refs.clear();

    let outcome = run(commission, packet, candidate).expect("bounded revision outcome");

    assert_eq!(outcome.progress, CycleProgress::Revise);
    assert!(
        outcome
            .review
            .checks
            .iter()
            .any(|check| !check.passed
                && check.check == cantor_ecosystem::ReviewCheckKind::Honesty)
    );
}

#[test]
fn expanded_work_packet_authority_is_rejected_before_any_message() {
    let (commission, mut packet, candidate) = standard_fixture();
    packet
        .authority_grant
        .effect_classes
        .insert("git_push".to_owned());

    let failure = run(commission, packet, candidate).expect_err("expanded authority");

    assert_eq!(failure.fault.code, EcosystemFaultCode::AuthorityDenied);
    assert!(failure.accepted_prefix.is_empty());
}

#[test]
fn expired_commission_is_rejected_before_any_message() {
    let (mut commission, packet, candidate) = standard_fixture();
    commission.lifecycle = cantor_ecosystem::CommissionLifecycle::Expired;

    let failure = run(commission, packet, candidate).expect_err("expired commission");

    assert_eq!(failure.fault.code, EcosystemFaultCode::CommissionInactive);
    assert!(failure.accepted_prefix.is_empty());
}

#[test]
fn message_limit_stops_the_cycle_at_its_first_over_budget_transition() {
    let (mut commission, mut packet, candidate) = standard_fixture();
    commission.budget.maximum_messages = 2;
    packet.budget.maximum_messages = 2;

    let failure = run(commission, packet, candidate).expect_err("message budget");

    assert_eq!(failure.fault.code, EcosystemFaultCode::BudgetExceeded);
    assert_eq!(failure.accepted_prefix.len(), 2);
    assert_eq!(failure.progress, CycleProgress::Assigned);
}

#[test]
fn call_depth_limit_stops_the_nested_cantor_query() {
    let (mut commission, mut packet, candidate) = standard_fixture();
    commission.budget.maximum_call_depth = 1;
    packet.budget.maximum_call_depth = 1;

    let failure = run(commission, packet, candidate).expect_err("depth budget");

    assert_eq!(failure.fault.code, EcosystemFaultCode::BudgetExceeded);
    assert_eq!(failure.accepted_prefix.len(), 2);
}

#[test]
fn logical_tick_limit_stops_the_cycle_deterministically() {
    let (mut commission, mut packet, candidate) = standard_fixture();
    commission.budget.maximum_logical_ticks = 2;
    packet.budget.maximum_logical_ticks = 2;

    let failure = run(commission, packet, candidate).expect_err("tick budget");

    assert_eq!(failure.fault.code, EcosystemFaultCode::BudgetExceeded);
    assert_eq!(failure.accepted_prefix.len(), 2);
}

#[test]
fn serialized_byte_limit_fails_before_partial_root_append() {
    let (mut commission, mut packet, candidate) = standard_fixture();
    commission.budget.maximum_serialized_bytes = 64;
    packet.budget.maximum_serialized_bytes = 64;

    let failure = run(commission, packet, candidate).expect_err("byte budget");

    assert_eq!(failure.fault.code, EcosystemFaultCode::BudgetExceeded);
    assert!(failure.accepted_prefix.is_empty());
}

#[test]
fn non_success_cantor_response_is_visible_as_adapter_failure() {
    let (commission, packet, candidate) = standard_fixture();
    let environment = common::environment();
    let request = protocol_request(&environment);
    let mut codex =
        MockCodexAdapter::new(packet.work_packet_uuid.clone(), request.clone(), candidate);
    let fault = cantor_core::ProtocolResponse::transport_fault(
        request.request_id.clone(),
        request.request.name(),
        cantor_core::ExitClass::PolicyDenial,
        "fixture_denial",
        "fixture denial",
    );
    let mut cantor = cantor_ecosystem::FunctionCantorAdapter::new(
        move |_request: &cantor_core::ProtocolRequest| Ok(fault.clone()),
    );

    let failure = cantor_ecosystem::run_supervised_mock_cycle(
        commission,
        packet,
        &cantor_ecosystem::CycleIdentityPlan::new("cycle:fault").expect("identity"),
        &mut codex,
        &mut cantor,
    )
    .expect_err("non-success response");

    assert_eq!(failure.fault.code, EcosystemFaultCode::ProtocolFault);
    assert_eq!(failure.accepted_prefix.len(), 3);
}

#[test]
fn mock_codex_rejects_repeated_assignment_stage() {
    let (_, packet, candidate) = standard_fixture();
    let environment = common::environment();
    let request = protocol_request(&environment);
    let mut codex = MockCodexAdapter::new(packet.work_packet_uuid.clone(), request, candidate);

    codex.accept_assignment(&packet).expect("first assignment");
    let fault = codex
        .accept_assignment(&packet)
        .expect_err("second assignment rejected");

    assert_eq!(fault.code, EcosystemFaultCode::AdapterFault);
    assert_eq!(codex.call_count(), 2);
}

#[test]
fn candidate_digest_validation_is_fail_closed() {
    let (commission, packet, mut candidate) = standard_fixture();
    candidate.content_digest = cantor_core::ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "not-a-digest".to_owned(),
    };

    let failure = run(commission, packet, candidate).expect_err("invalid candidate digest");

    assert_eq!(failure.fault.code, EcosystemFaultCode::InvalidDigest);
    assert_eq!(failure.accepted_prefix.len(), 4);
}

#[test]
fn unknown_json_fields_are_rejected_by_machine_forms() {
    let (_, packet, _) = standard_fixture();
    let mut value = serde_json::to_value(packet).expect("packet JSON");
    value
        .as_object_mut()
        .expect("packet object")
        .insert("unrecognized".to_owned(), serde_json::Value::Bool(true));

    let error = serde_json::from_value::<cantor_ecosystem::WorkPacket>(value)
        .expect_err("unknown field rejected");

    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn authority_intersection_never_creates_effect_authority() {
    let broad = common::authority();
    let mut other = broad.clone();
    other.effect_classes = ["git_push".to_owned()].into_iter().collect();
    other.semantic_operations = ["inspect".to_owned(), "query".to_owned()]
        .into_iter()
        .collect();

    let intersection = broad.intersection(&other);

    assert_eq!(
        intersection.semantic_operations,
        ["inspect".to_owned()].into_iter().collect::<BTreeSet<_>>()
    );
    assert!(intersection.effect_classes.is_empty());
    assert!(broad.contains(&intersection));
}

#[test]
fn candidate_content_digest_is_stable_fixture_data() {
    assert_eq!(
        candidate().content_digest,
        sha256_bytes(b"deterministic candidate")
    );
}

#[test]
fn mock_codex_rejects_a_return_bound_to_another_request() {
    let (_, packet, candidate) = standard_fixture();
    let environment = common::environment();
    let request = protocol_request(&environment);
    let mut other_request = request.clone();
    other_request.request_id = id("request:other");
    let response = cantor_core::execute_protocol_request(&environment, request.clone());
    let mut codex = MockCodexAdapter::new(packet.work_packet_uuid.clone(), request, candidate);
    codex.accept_assignment(&packet).expect("assignment");

    let fault = codex
        .accept_cantor_return(&other_request, &response)
        .expect_err("request mismatch");

    assert_eq!(fault.code, EcosystemFaultCode::AdapterFault);
}

#[test]
fn mock_codex_rejects_a_return_before_assignment() {
    let (_, packet, candidate) = standard_fixture();
    let environment = common::environment();
    let request = protocol_request(&environment);
    let response = cantor_core::execute_protocol_request(&environment, request.clone());
    let mut codex =
        MockCodexAdapter::new(packet.work_packet_uuid.clone(), request.clone(), candidate);

    let fault = codex
        .accept_cantor_return(&request, &response)
        .expect_err("premature return");

    assert_eq!(fault.code, EcosystemFaultCode::AdapterFault);
}

#[test]
fn unknown_criterion_claim_forces_honesty_revision() {
    let (commission, packet, mut candidate) = standard_fixture();
    candidate
        .satisfied_criterion_ids
        .insert(id("criterion:invented"));

    let outcome = run(commission, packet, candidate).expect("bounded revision outcome");

    assert_eq!(outcome.progress, CycleProgress::Revise);
    assert!(
        outcome
            .review
            .checks
            .iter()
            .any(|check| { !check.passed && check.check == ReviewCheckKind::Honesty })
    );
}

#[test]
fn contradictory_duplicate_review_checks_are_invalid() {
    let (commission, packet, candidate) = standard_fixture();
    let mut outcome = run(commission, packet, candidate).expect("successful cycle");
    outcome.review.checks[1] = ReviewCheck {
        check: ReviewCheckKind::Honesty,
        passed: false,
        detail: "contradictory duplicate".to_owned(),
    };
    outcome.review.disposition = ReviewDisposition::Revise;
    outcome.review.reasons = vec!["contradictory duplicate".to_owned()];

    let fault = outcome
        .review
        .validate()
        .expect_err("duplicate review check");

    assert_eq!(fault.code, EcosystemFaultCode::DuplicateIdentity);
}

#[test]
fn serialized_outcome_replays_as_one_coherent_proof_object() {
    let (commission, packet, candidate) = standard_fixture();
    let outcome = run(commission.clone(), packet.clone(), candidate).expect("successful cycle");
    let encoded = serde_json::to_vec(&outcome).expect("serialize outcome");
    let decoded: cantor_ecosystem::CycleOutcome =
        serde_json::from_slice(&encoded).expect("deserialize outcome");

    decoded
        .validate(&commission, &packet)
        .expect("coherent transported outcome");
}

#[test]
fn rewritten_outcome_metrics_are_rejected() {
    let (commission, packet, candidate) = standard_fixture();
    let mut outcome = run(commission.clone(), packet.clone(), candidate).expect("successful cycle");
    outcome.metrics.serialized_bytes += 1;

    let fault = outcome
        .validate(&commission, &packet)
        .expect_err("rewritten metrics");

    assert_eq!(fault.code, EcosystemFaultCode::OutcomeMismatch);
}

#[test]
fn top_level_candidate_cannot_diverge_from_the_transcript() {
    let (commission, packet, candidate) = standard_fixture();
    let mut outcome = run(commission.clone(), packet.clone(), candidate).expect("successful cycle");
    outcome.candidate.summary = "rewritten outside transcript".to_owned();

    let fault = outcome
        .validate(&commission, &packet)
        .expect_err("candidate divergence");

    assert_eq!(fault.code, EcosystemFaultCode::OutcomeMismatch);
}

#[test]
fn final_reason_cannot_be_rewritten_even_if_both_copies_change() {
    let (commission, packet, candidate) = standard_fixture();
    let mut outcome = run(commission.clone(), packet.clone(), candidate).expect("successful cycle");
    outcome.final_decision.reason = "accept without explanation".to_owned();
    let cantor_ecosystem::MessagePayload::Decision(decision) = &mut outcome.transcript[6].payload
    else {
        panic!("decision payload");
    };
    decision.reason = outcome.final_decision.reason.clone();

    let fault = outcome
        .validate(&commission, &packet)
        .expect_err("rewritten reason");

    assert_eq!(fault.code, EcosystemFaultCode::OutcomeMismatch);
}
