mod common;

use cantor_core::{ContentDigest, sha256_bytes};
use cantor_ecosystem::{
    AcceptanceCriterion, CommissionLifecycle, EcosystemFaultCode, MessageKind, MessagePayload,
    ParticipantRole, ReviewCheckKind,
};

use common::{
    address, assert_fault, assignment_envelope, id, root_envelope, standard_fixture, transcript,
};

#[test]
fn wrong_consumer_cannot_accept_an_addressed_message() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let root = root_envelope(&commission, &packet);

    let fault = transcript
        .append_for(&packet.worker, root)
        .expect_err("wrong consumer");

    assert_fault(&fault, EcosystemFaultCode::WrongRecipient);
    assert!(transcript.messages().is_empty());
}

#[test]
fn stale_frame_is_rejected_without_append() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.frame_digest = sha256_bytes(b"stale frame");

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("stale frame");

    assert_fault(&fault, EcosystemFaultCode::FrameMismatch);
    assert!(transcript.messages().is_empty());
}

#[test]
fn correlation_mismatch_is_rejected_without_append() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.correlation_uuid = id("commission:other");

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("correlation mismatch");

    assert_fault(&fault, EcosystemFaultCode::CorrelationMismatch);
    assert!(transcript.messages().is_empty());
}

#[test]
fn unknown_causal_predecessor_is_rejected() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    assignment.causation_uuid = Some(id("message:missing"));

    let fault = transcript
        .append_for(&packet.worker, assignment)
        .expect_err("broken causation");

    assert_fault(&fault, EcosystemFaultCode::BrokenCausation);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn causal_predecessor_must_hand_control_to_the_sender() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    transcript
        .append_for(&packet.worker, assignment_envelope(&commission, &packet))
        .expect("assignment");
    let mut assignment = assignment_envelope(&commission, &packet);
    assignment.message_uuid = id("message:assignment:invalid_handoff");
    assignment.idempotency_key = id("idempotency:assignment:invalid_handoff");
    assignment.causation_uuid = Some(id("message:assignment"));
    assignment.subject = "different semantic state".to_owned();
    assignment.logical_tick = 103;
    assignment
        .expected_response
        .as_mut()
        .expect("expected response")
        .deadline_tick = 104;

    let fault = transcript
        .append_for(&packet.worker, assignment)
        .expect_err("causal participant mismatch");

    assert_fault(&fault, EcosystemFaultCode::BrokenCausation);
    assert_eq!(transcript.messages().len(), 2);
}

#[test]
fn non_monotonic_logical_time_is_rejected() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    assignment.logical_tick = 101;

    let fault = transcript
        .append_for(&packet.worker, assignment)
        .expect_err("non-monotonic time");

    assert_fault(&fault, EcosystemFaultCode::NonMonotonicTick);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn response_deadline_cannot_exceed_commission_expiry() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.expected_response
        .as_mut()
        .expect("expected response")
        .deadline_tick = commission.expires_at_tick + 1;

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("deadline past expiry");

    assert_fault(&fault, EcosystemFaultCode::InvalidLifetime);
    assert!(transcript.messages().is_empty());
}

#[test]
fn duplicate_message_identity_is_rejected_before_append() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let assignment = assignment_envelope(&commission, &packet);
    transcript
        .append_for(&packet.worker, assignment.clone())
        .expect("assignment");
    let mut replay = assignment;
    replay.logical_tick = 103;
    replay
        .expected_response
        .as_mut()
        .expect("expected response")
        .deadline_tick = 104;

    let fault = transcript
        .append_for(&packet.worker, replay)
        .expect_err("message replay");

    assert_fault(&fault, EcosystemFaultCode::MessageReplay);
    assert_eq!(transcript.messages().len(), 2);
}

#[test]
fn duplicate_idempotency_identity_is_rejected_before_append() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let assignment = assignment_envelope(&commission, &packet);
    transcript
        .append_for(&packet.worker, assignment.clone())
        .expect("assignment");
    let mut replay = assignment;
    replay.message_uuid = id("message:assignment:retry");
    replay.logical_tick = 103;
    replay
        .expected_response
        .as_mut()
        .expect("expected response")
        .deadline_tick = 104;

    let fault = transcript
        .append_for(&packet.worker, replay)
        .expect_err("idempotency replay");

    assert_fault(&fault, EcosystemFaultCode::IdempotencyReplay);
    assert_eq!(transcript.messages().len(), 2);
}

#[test]
fn equivalent_semantic_state_is_rejected_as_cycle() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let assignment = assignment_envelope(&commission, &packet);
    transcript
        .append_for(&packet.worker, assignment.clone())
        .expect("assignment");
    let mut cycle = assignment;
    cycle.message_uuid = id("message:assignment:cycle");
    cycle.idempotency_key = id("idempotency:assignment:cycle");
    cycle.logical_tick = 103;
    cycle
        .expected_response
        .as_mut()
        .expect("expected response")
        .deadline_tick = 104;

    let fault = transcript
        .append_for(&packet.worker, cycle)
        .expect_err("semantic cycle");

    assert_fault(&fault, EcosystemFaultCode::SemanticCycle);
    assert_eq!(transcript.messages().len(), 2);
}

#[test]
fn participant_outside_the_work_packet_is_rejected() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    let unknown = address(ParticipantRole::CodexThread, "codex:unknown");
    assignment.recipient = unknown.clone();

    let fault = transcript
        .append_for(&unknown, assignment)
        .expect_err("unknown participant");

    assert_fault(&fault, EcosystemFaultCode::InvalidParticipant);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn payload_kind_mismatch_is_rejected_locally() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.message_kind = MessageKind::Candidate;

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("payload mismatch");

    assert_fault(&fault, EcosystemFaultCode::PayloadKindMismatch);
    assert!(transcript.messages().is_empty());
}

#[test]
fn unsupported_message_profile_is_rejected_locally() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.profile = "cantor-ecosystem-message/999".to_owned();

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("profile mismatch");

    assert_fault(&fault, EcosystemFaultCode::UnsupportedProfile);
    assert!(transcript.messages().is_empty());
}

#[test]
fn noncanonical_digest_is_rejected_locally() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.frame_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "A".repeat(64),
    };

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("noncanonical digest");

    assert_fault(&fault, EcosystemFaultCode::InvalidDigest);
    assert!(transcript.messages().is_empty());
}

#[test]
fn message_authority_cannot_expand_past_work_packet() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    assignment
        .authority_scope
        .effect_classes
        .insert("git_push".to_owned());

    let fault = transcript
        .append_for(&packet.worker, assignment)
        .expect_err("authority expansion");

    assert_fault(&fault, EcosystemFaultCode::AuthorityDenied);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn effect_broker_is_not_a_known_phase_one_participant() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    let effect_broker = address(ParticipantRole::EffectBroker, "effect:broker");
    assignment.recipient = effect_broker.clone();

    let fault = transcript
        .append_for(&effect_broker, assignment)
        .expect_err("effect broker unavailable");

    assert_fault(&fault, EcosystemFaultCode::InvalidParticipant);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn root_message_cannot_claim_a_causal_predecessor() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.causation_uuid = Some(id("message:invented"));

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("root causation");

    assert_fault(&fault, EcosystemFaultCode::UnexpectedMessage);
    assert!(transcript.messages().is_empty());
}

#[test]
fn duplicate_acceptance_criterion_identity_is_rejected() {
    let (commission, mut packet, _) = standard_fixture();
    packet.acceptance_criteria.push(AcceptanceCriterion {
        criterion_id: id("criterion:protocol"),
        description: "duplicate identity".to_owned(),
    });

    let fault = packet
        .validate(&commission)
        .expect_err("duplicate criterion");

    assert_fault(&fault, EcosystemFaultCode::DuplicateIdentity);
}

#[test]
fn root_payload_must_equal_the_active_commission() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    let MessagePayload::Commission(payload) = &mut root.payload else {
        panic!("commission payload");
    };
    payload.purpose = "different purpose".to_owned();

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("different commission");

    assert_fault(&fault, EcosystemFaultCode::UnexpectedMessage);
    assert!(transcript.messages().is_empty());
}

#[test]
fn invalid_assignment_payload_does_not_modify_transcript() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    let MessagePayload::Assignment(payload) = &mut assignment.payload else {
        panic!("assignment payload");
    };
    payload.frame_digest = sha256_bytes(b"different packet frame");

    let fault = transcript
        .append_for(&packet.worker, assignment)
        .expect_err("different packet");

    assert_fault(&fault, EcosystemFaultCode::CorrelationMismatch);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn known_participants_cannot_use_the_wrong_message_route() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    assignment.sender = packet.cantor_participant.clone();

    let fault = transcript
        .append_for(&packet.worker, assignment)
        .expect_err("wrong fixed route");

    assert_fault(&fault, EcosystemFaultCode::WrongRecipient);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn response_kind_must_match_the_causal_contract() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.expected_response
        .as_mut()
        .expect("expected response")
        .message_kind = MessageKind::Review;

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("response kind mismatch");

    assert_fault(&fault, EcosystemFaultCode::UnexpectedMessage);
    assert!(transcript.messages().is_empty());
}

#[test]
fn causal_predecessor_without_a_response_contract_cannot_be_extended() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.expected_response = None;
    transcript
        .append_for(&commission.manager, root)
        .expect("bounded incomplete root");

    let fault = transcript
        .append_for(&packet.worker, assignment_envelope(&commission, &packet))
        .expect_err("undeclared response");

    assert_fault(&fault, EcosystemFaultCode::UnexpectedMessage);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn response_after_the_declared_deadline_is_rejected() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    transcript
        .append_for(&commission.manager, root_envelope(&commission, &packet))
        .expect("root");
    let mut assignment = assignment_envelope(&commission, &packet);
    assignment.logical_tick = 103;
    assignment
        .expected_response
        .as_mut()
        .expect("expected response")
        .deadline_tick = 104;

    let fault = transcript
        .append_for(&packet.worker, assignment)
        .expect_err("late response");

    assert_fault(&fault, EcosystemFaultCode::CommissionExpired);
    assert_eq!(transcript.messages().len(), 1);
}

#[test]
fn phase_one_fault_envelopes_are_not_admitted_as_hidden_control_flow() {
    let (commission, packet, _) = standard_fixture();
    let mut transcript = transcript(&commission, &packet);
    let mut root = root_envelope(&commission, &packet);
    root.message_kind = MessageKind::Fault;
    root.payload = MessagePayload::Fault(Box::new(cantor_ecosystem::EcosystemFault::new(
        EcosystemFaultCode::AdapterFault,
        "fixture",
        "fixture fault",
        vec![],
    )));

    let fault = transcript
        .append_for(&commission.manager, root)
        .expect_err("fault envelope");

    assert_fault(&fault, EcosystemFaultCode::UnexpectedMessage);
    assert!(transcript.messages().is_empty());
}

#[test]
fn commission_cannot_grant_effect_authority_in_phase_one() {
    let (mut commission, _, _) = standard_fixture();
    commission
        .authority_grant
        .effect_classes
        .insert("git_push".to_owned());

    let fault = commission
        .validate(commission.activated_at_tick)
        .expect_err("effect authority");

    assert_fault(&fault, EcosystemFaultCode::AuthorityDenied);
}

#[test]
fn every_nonactive_commission_lifecycle_is_rejected() {
    for lifecycle in [
        CommissionLifecycle::Revoked,
        CommissionLifecycle::Expired,
        CommissionLifecycle::Completed,
        CommissionLifecycle::Faulted,
    ] {
        let (mut commission, _, _) = standard_fixture();
        commission.lifecycle = lifecycle;

        let fault = commission
            .validate(commission.activated_at_tick)
            .expect_err("inactive commission");

        assert_fault(&fault, EcosystemFaultCode::CommissionInactive);
    }
}

#[test]
fn commission_time_must_be_inside_the_declared_lifetime() {
    let (commission, _, _) = standard_fixture();

    let before = commission
        .validate(commission.activated_at_tick - 1)
        .expect_err("before activation");
    let after = commission
        .validate(commission.expires_at_tick + 1)
        .expect_err("after expiry");

    assert_fault(&before, EcosystemFaultCode::CommissionExpired);
    assert_fault(&after, EcosystemFaultCode::CommissionExpired);
}

#[test]
fn mandatory_observer_check_cannot_be_omitted() {
    let (mut commission, _, _) = standard_fixture();
    commission
        .required_review_checks
        .remove(&ReviewCheckKind::Honesty);

    let fault = commission
        .validate(commission.activated_at_tick)
        .expect_err("missing mandatory check");

    assert_fault(&fault, EcosystemFaultCode::MissingReviewCheck);
}

#[test]
fn zero_message_budget_is_rejected() {
    let (mut commission, _, _) = standard_fixture();
    commission.budget.maximum_messages = 0;

    let fault = commission
        .validate(commission.activated_at_tick)
        .expect_err("zero message budget");

    assert_fault(&fault, EcosystemFaultCode::InvalidBudget);
}

#[test]
fn authority_dimension_cardinality_is_bounded() {
    let (mut commission, _, _) = standard_fixture();
    commission.authority_grant.projects =
        (0..257).map(|index| format!("project:{index}")).collect();

    let fault = commission
        .validate(commission.activated_at_tick)
        .expect_err("oversized authority dimension");

    assert_fault(&fault, EcosystemFaultCode::BudgetExceeded);
}

#[test]
fn acceptance_criterion_cardinality_is_bounded() {
    let (commission, mut packet, _) = standard_fixture();
    packet.acceptance_criteria = (0..257)
        .map(|index| AcceptanceCriterion {
            criterion_id: id(&format!("criterion:{index}")),
            description: format!("criterion {index}"),
        })
        .collect();

    let fault = packet
        .validate(&commission)
        .expect_err("oversized criterion set");

    assert_fault(&fault, EcosystemFaultCode::BudgetExceeded);
}
