use std::collections::{BTreeMap, BTreeSet};

use cantor_core::*;
use sha2::{Digest, Sha256};

const RELEASE_MATRIX: &str =
    include_str!("../../../feature_support/Cantor_Process_Procedure_Experiment_Release_Matrix.sop");
const SIGNED_REQUIREMENT_MATRIX: &str = include_str!(
    "../../../feature_support/Cantor_Process_Procedure_Experiment_Requirement_Matrix.sop"
);

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn model_candidate() -> ProcedureCandidate {
    let mut candidate: ProcedureCandidate =
        serde_json::from_str(include_str!("fixtures/cppe_two_process_candidate.json"))
            .expect("checked two-process candidate fixture");
    candidate.candidate_id = sid("release-candidate:model-shaped");
    candidate.author_ref = sid("model-output:release-procedure-author");
    candidate.provenance_refs = BTreeSet::from([sid("evidence:model-shaped-release-output")]);
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).expect("candidate source digest");
    candidate
}

fn release_template() -> AuthorshipLaneTemplate {
    AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:model-shaped-release-output")]),
        validator_ref: sid("validator:independent-release-fixture"),
        policy_ref: sid("policy:release-fixture"),
        aliases: BTreeSet::from(["release-fixture".to_owned()]),
        permitted_invocation_context: "effectless-release-audit".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("release-invocation:model-shaped"),
        caller_ref: sid("caller:release-controller"),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:release-fixture"),
        initial_logical_time: 30,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention"),
        session_generation_ref: sid("release-session-generation:model-shaped"),
        session_ref: sid("release-session:model-shaped"),
        session_purpose: "audit the bounded effectless experiment".to_owned(),
        frame_ref: sid("release-frame:model-shaped"),
        frame_conditions: BTreeSet::from(["effectless".to_owned()]),
        frame_constraints: BTreeSet::from(["bounded-internal-fixture".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    }
}

fn lane() -> AuthorshipLaneEvidence {
    run_authorship_lane(&model_candidate(), &release_template(), &BTreeMap::new())
        .expect("release lane")
}

fn proposal(schema: &ProviderNeutralToolSchema, lane: &AuthorshipLaneEvidence) -> ToolCallProposal {
    let mut proposal = ToolCallProposal {
        schema_ref: schema.schema_id.clone(),
        schema_digest: schema.schema_digest.clone(),
        call_id: sid("release-tool-call:reconcile"),
        inference_job_ref: sid("release-inference-job:fixture"),
        participant_ref: lane.request.caller_ref.clone(),
        pass_index: 5,
        operation: ExchangeOperation::Reconcile,
        invocation: lane.request.clone(),
        session: lane.initial_session.clone(),
        argument_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    };
    proposal.argument_digest =
        compute_tool_call_argument_digest(&proposal).expect("argument digest");
    proposal
}

#[test]
fn release_matrix_has_one_bounded_evidence_record_for_every_requirement() {
    let records = RELEASE_MATRIX
        .lines()
        .filter(|line| line.trim_start().starts_with("+ [CPPE-"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 40);
    for number in 1..=40 {
        let identity = format!("[CPPE-{number:03}]");
        let matches = records
            .iter()
            .filter(|line| line.contains(&identity))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "release record {identity}");
        let record = matches[0];
        assert!(record.contains("status=verified"));
        assert!(record.contains("grade="));
        assert!(record.contains("evidence="));
        assert!(record.contains("residual="));
    }
    assert!(RELEASE_MATRIX.contains("[production_verified_count] is 0"));
    assert!(RELEASE_MATRIX.contains("[live_provider_verified_count] is 0"));
    assert!(RELEASE_MATRIX.contains("[external_effect_verified_count] is 0"));
    assert!(RELEASE_MATRIX.contains("[hardware_verified_count] is 0"));
}

#[test]
fn signed_requirement_matrix_remains_the_exact_preimplementation_authority() {
    assert_eq!(SIGNED_REQUIREMENT_MATRIX.len(), 4033);
    assert_eq!(
        Sha256::digest(SIGNED_REQUIREMENT_MATRIX.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "8623d4773251f6050f5e8a6a6266463bc8e65699c2b590310a2909c34c66da14"
    );
    assert!(SIGNED_REQUIREMENT_MATRIX.contains("[procedure_implementation_status] is not_started"));
    assert!(!SIGNED_REQUIREMENT_MATRIX.contains("bounded_internal_fixture"));
}

#[test]
fn release_lane_preserves_authority_sensitivity_retention_and_effect_boundaries() {
    let lane = lane();
    let principals = BTreeSet::from([
        lane.candidate.author_ref.clone(),
        lane.validation.validator_ref.clone(),
        lane.compilation.compiler_ref.clone(),
        lane.verification.verifier_ref.clone(),
        lane.admission.observer_ref.clone(),
        lane.catalogue_receipt.principal_ref.clone(),
        lane.replay.coordinator_ref.clone(),
        sid(CPPE_FAKE_TOOL_CONTROLLER_ID),
    ]);
    assert_eq!(principals.len(), 8);
    assert_eq!(
        lane.candidate.sensitivity,
        SensitivityClass::ProjectInternal
    );
    assert_eq!(lane.request.input_sensitivity, lane.candidate.sensitivity);
    assert_eq!(
        lane.request.retention_policy_ref,
        lane.candidate.retention_policy_ref
    );
    assert_eq!(
        lane.coordination.result.retention_policy_ref,
        lane.request.retention_policy_ref
    );
    assert_eq!(
        lane.candidate.effects.effect_class,
        ProcedureEffectClass::Effectless
    );
    assert_eq!(
        lane.candidate.effects.allowed_read_classes,
        BTreeSet::from([
            ProcedureReadClass::TypedInvocationInput,
            ProcedureReadClass::PinnedAdmittedInMemoryArtifact,
        ])
    );
    assert_eq!(
        lane.candidate.effects.allowed_write_classes,
        BTreeSet::from([
            ProcedureWriteClass::ReturnedValue,
            ProcedureWriteClass::Message,
            ProcedureWriteClass::StateSuccessor,
            ProcedureWriteClass::SemanticTrace,
            ProcedureWriteClass::Receipt,
            ProcedureWriteClass::Fault,
        ])
    );
    assert_eq!(
        lane.candidate.effects.prohibited_operations,
        all_prohibited()
    );
    assert_eq!(all_prohibited().len(), 24);

    let schema = provider_neutral_exchange_schema().expect("tool schema");
    let proposal = proposal(&schema, &lane);
    let outcome = run_fake_controller_exchange(&schema, &proposal, &lane).expect("tool outcome");
    verify_fake_controller_outcome(&schema, &proposal, &lane, &outcome)
        .expect("verified tool outcome");
    assert_eq!(outcome.transcript.provider_call_count, 0);
    assert_eq!(outcome.transcript.external_effect_count, 0);
    assert_eq!(
        outcome
            .result
            .explicit_context
            .as_ref()
            .expect("explicit context")
            .sensitivity,
        lane.candidate.sensitivity
    );
}

#[test]
fn every_lifecycle_authority_is_distinct_and_content_linked() {
    let lane = lane();
    let phase_ids = BTreeSet::from([
        lane.validation.receipt_id.clone(),
        lane.compilation.receipt_id.clone(),
        lane.verification.receipt_id.clone(),
        lane.admission.disposition_id.clone(),
        lane.catalogue_receipt.receipt_id.clone(),
        lane.request.invocation_id.clone(),
        lane.replay.receipt_id.clone(),
    ]);
    assert_eq!(phase_ids.len(), 7);
    assert_eq!(
        lane.compilation.validation_receipt_ref,
        lane.validation.receipt_id
    );
    assert_eq!(
        lane.verification.compilation_receipt_ref,
        lane.compilation.receipt_id
    );
    assert_eq!(
        lane.admission.validation_receipt_ref,
        lane.validation.receipt_id
    );
    assert_eq!(
        lane.admission.compilation_receipt_ref,
        lane.compilation.receipt_id
    );
    assert_eq!(
        lane.admission.verification_receipt_ref,
        lane.verification.receipt_id
    );
    assert_eq!(
        lane.catalogue_receipt.admission_disposition_ref,
        lane.admission.disposition_id
    );
    assert_eq!(
        lane.request.admission_disposition_ref,
        lane.admission.disposition_id
    );
    assert!(lane.replay.matched);
    assert_eq!(
        lane.stable_session.status,
        NegotiationStatus::StableCandidate
    );
}

#[test]
fn release_replay_is_exact_and_negative_calls_never_resume() {
    let first_lane = lane();
    let second_lane = lane();
    assert_eq!(first_lane, second_lane);
    let schema = provider_neutral_exchange_schema().expect("tool schema");
    let proposal = proposal(&schema, &first_lane);
    let first = run_fake_controller_exchange(&schema, &proposal, &first_lane).expect("tool run");
    let second =
        run_fake_controller_exchange(&schema, &proposal, &first_lane).expect("tool replay");
    assert_eq!(first, second);

    let mut stale = proposal;
    stale.invocation.catalogue_generation_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "00".repeat(32),
    };
    stale.argument_digest = compute_tool_call_argument_digest(&stale).expect("stale digest");
    let refused =
        run_fake_controller_exchange(&schema, &stale, &first_lane).expect("typed refusal");
    assert_eq!(refused.result.disposition, ToolResultDisposition::Refused);
    assert!(refused.coordination.is_none());
    assert!(!refused.transcript.events.iter().any(|event| matches!(
        event.kind,
        ControllerEventKind::CantorInvoked | ControllerEventKind::LaterPassResumed
    )));
}

fn all_prohibited() -> BTreeSet<ProhibitedProcedureOperation> {
    BTreeSet::from([
        ProhibitedProcedureOperation::Recursion,
        ProhibitedProcedureOperation::UnboundedIteration,
        ProhibitedProcedureOperation::UnrestrictedInheritance,
        ProhibitedProcedureOperation::DynamicAllocation,
        ProhibitedProcedureOperation::PointerAccess,
        ProhibitedProcedureOperation::NativeStackCapture,
        ProhibitedProcedureOperation::SelfModification,
        ProhibitedProcedureOperation::RuntimeCodeLoading,
        ProhibitedProcedureOperation::ExecutableReflection,
        ProhibitedProcedureOperation::UndeclaredStorage,
        ProhibitedProcedureOperation::SystemClock,
        ProhibitedProcedureOperation::Randomness,
        ProhibitedProcedureOperation::Environment,
        ProhibitedProcedureOperation::Filesystem,
        ProhibitedProcedureOperation::Network,
        ProhibitedProcedureOperation::Database,
        ProhibitedProcedureOperation::Subprocess,
        ProhibitedProcedureOperation::Provider,
        ProhibitedProcedureOperation::Notification,
        ProhibitedProcedureOperation::Git,
        ProhibitedProcedureOperation::Model,
        ProhibitedProcedureOperation::UnsafeCode,
        ProhibitedProcedureOperation::Device,
        ProhibitedProcedureOperation::ExternalEffect,
    ])
}
