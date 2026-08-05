//! Effectless authorship-parity harness for CPPE-I07.
//!
//! A model-shaped candidate is supplied data with explicit provenance. This
//! module never calls a model and grants authorship no validation, verification,
//! admission, catalogue, invocation, or effect authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::procedure_runtime::{derived_id, digest_serialized, empty_sha256, machine_fault};
use crate::{
    AdmissionDecision, AdmissionDisposition, CPPE_COMPILER_ID, CPPE_COORDINATOR_ID,
    CPPE_FAKE_OBSERVER_ID, CPPE_FORM_VERSION, CPPE_VERIFIER_ID, CantorProcessIr, CatalogueReceipt,
    CompilationReceipt, CompiledProcedureIdentity, ConsumedBudget, ContentDigest,
    CoordinationOutcome, CoordinationReplayReceipt, EvaluationFault, FakeObserverAdmissionPolicy,
    InvocationBudget, InvocationDisposition, InvocationRequest, NegotiatedFrame,
    NegotiationSession, NegotiationStatus, Participant, PhaseDisposition, ProcedureCandidate,
    ProcedureCatalogueState, ProcedureFormSet, ProcedureMessageKind, ProcedureSchemaSet,
    ProcedureValue, ProcessLifecycle, ReceiptEvidence, SemanticId, SensitivityClass, TokenRingPass,
    TraceEventKind, ValidationReceipt, VerificationReceipt, build_fake_observer_policy,
    compile_procedure_candidate, compute_candidate_source_digest,
    compute_compilation_receipt_digest, compute_effect_declaration_digest,
    compute_procedure_bounds_digest, compute_validation_receipt_digest,
    compute_verification_receipt_digest, coordinate_catalogued_procedure,
    empty_procedure_catalogue, fake_observer_admit, insert_admitted_procedure,
    record_token_ring_pass, validate_procedure_forms, verify_compiled_procedure,
    verify_coordination_replay,
};

pub const CPPE_AUTHORSHIP_PARITY_ID: &str = "cantor-authorship-parity/0.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorshipClass {
    HandAuthored,
    ModelShaped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorshipLaneTemplate {
    pub class: AuthorshipClass,
    pub authorship_evidence_refs: BTreeSet<SemanticId>,
    pub validator_ref: SemanticId,
    pub policy_ref: SemanticId,
    pub aliases: BTreeSet<String>,
    pub permitted_invocation_context: String,
    pub revocation_conditions: BTreeSet<String>,
    pub invocation_ref: SemanticId,
    pub caller_ref: SemanticId,
    pub input: ProcedureValue,
    pub input_sensitivity: SensitivityClass,
    pub sop_generation_ref: SemanticId,
    pub initial_logical_time: u64,
    pub budgets: InvocationBudget,
    pub retention_policy_ref: SemanticId,
    pub session_generation_ref: SemanticId,
    pub session_ref: SemanticId,
    pub session_purpose: String,
    pub frame_ref: SemanticId,
    pub frame_conditions: BTreeSet<String>,
    pub frame_constraints: BTreeSet<String>,
    pub permitted_message_kinds: BTreeSet<ProcedureMessageKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorshipLaneEvidence {
    pub class: AuthorshipClass,
    pub authorship_evidence_refs: BTreeSet<SemanticId>,
    pub recognized_anchors: BTreeMap<SemanticId, crate::SopAnchorBinding>,
    pub aliases: BTreeSet<String>,
    pub candidate: ProcedureCandidate,
    pub validation: ValidationReceipt,
    pub compilation: CompilationReceipt,
    pub ir: CantorProcessIr,
    pub procedure: CompiledProcedureIdentity,
    pub verification: VerificationReceipt,
    pub policy: FakeObserverAdmissionPolicy,
    pub admission: AdmissionDisposition,
    pub catalogue_receipt: CatalogueReceipt,
    pub catalogue: ProcedureCatalogueState,
    pub request: InvocationRequest,
    pub initial_session: NegotiationSession,
    pub coordination: CoordinationOutcome,
    pub token_passes: BTreeMap<SemanticId, TokenRingPass>,
    pub stable_session: NegotiationSession,
    pub replay: CoordinationReplayReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorTraceProjection {
    pub kind: TraceEventKind,
    pub subject_generation: u64,
    pub payload_digest: ContentDigest,
    pub causal_predecessor_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorStepProjection {
    pub instruction_ref: SemanticId,
    pub input_generation: u64,
    pub input_message_count: u64,
    pub emitted_message_count: u64,
    pub returned_value: Option<ProcedureValue>,
    pub faulted: bool,
    pub logical_time_before: u64,
    pub logical_time_after: u64,
    pub consumed_budget: ConsumedBudget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorMessageProjection {
    pub sender_ref: SemanticId,
    pub receiver_ref: SemanticId,
    pub frame_generation: u64,
    pub kind: ProcedureMessageKind,
    pub payload_digest: ContentDigest,
    pub logical_time: u64,
    pub expires_at_logical_time: u64,
    pub causal_predecessor_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorContinuationProjection {
    pub definition_ref: SemanticId,
    pub generation: u64,
    pub region_ref: SemanticId,
    pub instruction_index: u64,
    pub lifecycle: ProcessLifecycle,
    pub awaited_shape: String,
    pub local_state_digest: ContentDigest,
    pub logical_time: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorshipBehaviorProjection {
    pub purpose: String,
    pub scope: BTreeSet<String>,
    pub language_profile: String,
    pub source_digest: ContentDigest,
    pub normalized_source_form: ProcedureValue,
    pub schema_set_digest: ContentDigest,
    pub process_definition_digest: ContentDigest,
    pub effect_declaration_digest: ContentDigest,
    pub bounds_digest: ContentDigest,
    pub sensitivity: SensitivityClass,
    pub retention_policy_ref: SemanticId,
    pub compilation_cost: BTreeMap<String, u64>,
    pub pipeline_principals: Vec<SemanticId>,
    pub phase_dispositions: Vec<PhaseDisposition>,
    pub admission_decision: AdmissionDecision,
    pub permitted_invocation_contexts: BTreeSet<String>,
    pub revocation_conditions: BTreeSet<String>,
    pub invocation_disposition: InvocationDisposition,
    pub output: Option<ProcedureValue>,
    pub consumed_budget: ConsumedBudget,
    pub residuals: BTreeSet<String>,
    pub trace: Vec<BehaviorTraceProjection>,
    pub steps: Vec<BehaviorStepProjection>,
    pub messages: Vec<BehaviorMessageProjection>,
    pub continuations: Vec<BehaviorContinuationProjection>,
    pub active_continuation_count: u64,
    pub token_participant_order: Vec<SemanticId>,
    pub stable_status: NegotiationStatus,
    pub stable_frame_generation: u64,
    pub replay_matched: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorshipParityReport {
    pub report_id: SemanticId,
    pub profile: String,
    pub hand_candidate_ref: SemanticId,
    pub model_candidate_ref: SemanticId,
    pub hand_projection_digest: ContentDigest,
    pub model_projection_digest: ContentDigest,
    pub axis_results: BTreeMap<String, bool>,
    pub disposition: PhaseDisposition,
    pub evidence_refs: BTreeSet<SemanticId>,
    pub residuals: BTreeSet<String>,
    pub report_digest: ContentDigest,
}

pub fn run_authorship_lane(
    candidate: &ProcedureCandidate,
    template: &AuthorshipLaneTemplate,
    recognized_anchors: &BTreeMap<SemanticId, crate::SopAnchorBinding>,
) -> Result<AuthorshipLaneEvidence, EvaluationFault> {
    validate_authorship_boundary(candidate, template)?;
    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(candidate.candidate_id.clone(), candidate.clone());
    validate_procedure_forms(&forms)?;
    if compute_candidate_source_digest(candidate)? != candidate.source_digest {
        return Err(machine_fault("authorship candidate source digest mismatch"));
    }

    let receipt_seed = digest_serialized(
        &(
            &candidate.candidate_id,
            &candidate.source_digest,
            &template.validator_ref,
            &template.authorship_evidence_refs,
        ),
        "authorship validation receipt",
    )?;
    let mut validation = ValidationReceipt {
        receipt_id: derived_id("cppe:authorship-validation", &receipt_seed)?,
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        validator_ref: template.validator_ref.clone(),
        profile: CPPE_FORM_VERSION.to_owned(),
        disposition: PhaseDisposition::Passed,
        evidence: ReceiptEvidence {
            evidence_refs: template.authorship_evidence_refs.clone(),
            residuals: BTreeSet::from([
                "authorship class grants no downstream authority".to_owned()
            ]),
            diagnostics: BTreeSet::from(["candidate machine form validated".to_owned()]),
        },
        receipt_digest: empty_sha256(),
    };
    validation.receipt_digest = compute_validation_receipt_digest(&validation)?;

    let compiled = compile_procedure_candidate(candidate, &validation)?;
    if compiled.compilation_receipt.disposition != PhaseDisposition::Passed {
        return Err(machine_fault(
            "authorship parity lane requires a compilable normalized candidate",
        ));
    }
    let ir = compiled
        .process_ir
        .ok_or_else(|| machine_fault("passed compilation omitted Process IR"))?;
    let procedure = compiled
        .compiled_procedure
        .ok_or_else(|| machine_fault("passed compilation omitted procedure identity"))?;
    let verification = verify_compiled_procedure(
        candidate,
        &validation,
        &compiled.compilation_receipt,
        &ir,
        &procedure,
        recognized_anchors,
    )?;
    if verification.disposition != PhaseDisposition::Passed
        || compute_verification_receipt_digest(&verification)? != verification.receipt_digest
    {
        return Err(machine_fault(
            "authorship parity lane did not pass independent verification",
        ));
    }
    let policy = build_fake_observer_policy(
        template.policy_ref.clone(),
        candidate,
        &ir,
        &procedure,
        AdmissionDecision::Admit,
        BTreeSet::from([template.permitted_invocation_context.clone()]),
        template.revocation_conditions.clone(),
    )?;
    let admission = fake_observer_admit(
        candidate,
        &validation,
        &compiled.compilation_receipt,
        &ir,
        &procedure,
        &verification,
        &policy,
    )?;
    if admission.decision != AdmissionDecision::Admit {
        return Err(machine_fault(
            "authorship parity lane did not receive fake Observer admission",
        ));
    }
    let catalogue_transition = insert_admitted_procedure(
        &empty_procedure_catalogue()?,
        &procedure,
        &admission,
        template.aliases.clone(),
    )?;
    let catalogue = catalogue_transition
        .successor
        .ok_or_else(|| machine_fault("passed catalogue insertion omitted successor"))?;
    let input_schema_ref = exact_schema_ref(&ir.schema_set, crate::SchemaKind::Input)?;
    let output_schema_ref = exact_schema_ref(&ir.schema_set, crate::SchemaKind::Output)?;
    let request = InvocationRequest {
        invocation_id: template.invocation_ref.clone(),
        caller_ref: template.caller_ref.clone(),
        purpose: template.permitted_invocation_context.clone(),
        admitted_procedure_ref: procedure.procedure_id.clone(),
        procedure_digest: procedure.procedure_digest.clone(),
        admission_disposition_ref: admission.disposition_id.clone(),
        admission_disposition_digest: admission.disposition_digest.clone(),
        input_schema_ref,
        schema_set_digest: ir.schema_set.schema_set_digest.clone(),
        input: template.input.clone(),
        input_sensitivity: template.input_sensitivity,
        sop_generation_ref: template.sop_generation_ref.clone(),
        sop_anchor_set_digest: admission.anchor_set_digest.clone(),
        policy_ref: admission.policy_ref.clone(),
        policy_digest: admission.policy_digest.clone(),
        participant_refs: ir.process_definitions.keys().cloned().collect(),
        initial_logical_time: template.initial_logical_time,
        budgets: template.budgets.clone(),
        expected_output_schema_ref: output_schema_ref,
        catalogue_generation_digest: catalogue.generation_digest.clone(),
        retention_policy_ref: template.retention_policy_ref.clone(),
    };
    let initial_session = build_session(&ir, &admission, template)?;
    let coordination = coordinate_catalogued_procedure(
        &catalogue,
        &procedure,
        &ir,
        &admission,
        &request,
        &initial_session,
    )?;
    if coordination.result.disposition != InvocationDisposition::Returned {
        return Err(machine_fault(
            "authorship parity lane coordination did not return",
        ));
    }
    let mut stable_session = coordination
        .session_successor
        .clone()
        .ok_or_else(|| machine_fault("coordination omitted session successor"))?;
    let mut token_passes = BTreeMap::new();
    let mut logical_time = request
        .initial_logical_time
        .saturating_add(coordination.result.consumed_budget.logical_time);
    while stable_session.status != NegotiationStatus::StableCandidate {
        logical_time = logical_time
            .checked_add(1)
            .ok_or_else(|| machine_fault("token pass logical time overflow"))?;
        let holder = stable_session.token_holder_ref.clone();
        let transition =
            record_token_ring_pass(&stable_session, &token_passes, &holder, logical_time)?;
        token_passes.insert(transition.pass.pass_id.clone(), transition.pass);
        stable_session = transition.successor;
        if token_passes.len() > stable_session.required_participant_refs.len() {
            return Err(machine_fault("token pass cycle exceeded participant bound"));
        }
    }
    let replay = verify_coordination_replay(
        &catalogue,
        &procedure,
        &ir,
        &admission,
        &request,
        &initial_session,
    )?;
    if !replay.matched {
        return Err(machine_fault("authorship lane replay did not match"));
    }
    Ok(AuthorshipLaneEvidence {
        class: template.class,
        authorship_evidence_refs: template.authorship_evidence_refs.clone(),
        recognized_anchors: recognized_anchors.clone(),
        aliases: template.aliases.clone(),
        candidate: candidate.clone(),
        validation,
        compilation: compiled.compilation_receipt,
        ir,
        procedure,
        verification,
        policy,
        admission,
        catalogue_receipt: catalogue_transition.receipt,
        catalogue,
        request,
        initial_session,
        coordination,
        token_passes,
        stable_session,
        replay,
    })
}

pub fn compare_authorship_lanes(
    hand: &AuthorshipLaneEvidence,
    model: &AuthorshipLaneEvidence,
) -> Result<AuthorshipParityReport, EvaluationFault> {
    if hand.class != AuthorshipClass::HandAuthored || model.class != AuthorshipClass::ModelShaped {
        return Err(machine_fault(
            "authorship parity requires one hand-authored and one model-shaped lane",
        ));
    }
    if hand.candidate.author_ref == model.candidate.author_ref {
        return Err(machine_fault(
            "authorship parity lanes require distinct declared authors",
        ));
    }
    let hand_projection = behavior_projection(hand)?;
    let model_projection = behavior_projection(model)?;
    let hand_projection_digest = digest_serialized(&hand_projection, "hand behavior projection")?;
    let model_projection_digest =
        digest_serialized(&model_projection, "model behavior projection")?;
    let axis_results = BTreeMap::from([
        (
            "semantic_source".to_owned(),
            hand_projection.source_digest == model_projection.source_digest
                && hand_projection.normalized_source_form
                    == model_projection.normalized_source_form,
        ),
        (
            "schema_effect_bounds".to_owned(),
            hand_projection.schema_set_digest == model_projection.schema_set_digest
                && hand_projection.effect_declaration_digest
                    == model_projection.effect_declaration_digest
                && hand_projection.bounds_digest == model_projection.bounds_digest,
        ),
        (
            "phase_dispositions".to_owned(),
            hand_projection.phase_dispositions == model_projection.phase_dispositions
                && hand_projection.admission_decision == model_projection.admission_decision
                && hand_projection.permitted_invocation_contexts
                    == model_projection.permitted_invocation_contexts
                && hand_projection.revocation_conditions == model_projection.revocation_conditions,
        ),
        (
            "pipeline_principals".to_owned(),
            hand_projection.pipeline_principals == model_projection.pipeline_principals,
        ),
        (
            "coordination_behavior".to_owned(),
            hand_projection.invocation_disposition == model_projection.invocation_disposition
                && hand_projection.output == model_projection.output
                && hand_projection.consumed_budget == model_projection.consumed_budget
                && hand_projection.trace == model_projection.trace
                && hand_projection.steps == model_projection.steps
                && hand_projection.messages == model_projection.messages
                && hand_projection.continuations == model_projection.continuations,
        ),
        (
            "token_and_replay".to_owned(),
            hand_projection.token_participant_order == model_projection.token_participant_order
                && hand_projection.stable_status == model_projection.stable_status
                && hand_projection.stable_frame_generation
                    == model_projection.stable_frame_generation
                && hand_projection.replay_matched == model_projection.replay_matched,
        ),
    ]);
    let passed = axis_results.values().all(|value| *value)
        && hand_projection_digest == model_projection_digest;
    let disposition = if passed {
        PhaseDisposition::Passed
    } else {
        PhaseDisposition::Refused
    };
    let evidence_refs = hand
        .authorship_evidence_refs
        .union(&model.authorship_evidence_refs)
        .cloned()
        .collect::<BTreeSet<_>>();
    let seed = digest_serialized(
        &(
            &hand.candidate.candidate_id,
            &model.candidate.candidate_id,
            &hand_projection_digest,
            &model_projection_digest,
            &axis_results,
            disposition,
            &evidence_refs,
        ),
        "authorship parity report",
    )?;
    let mut report = AuthorshipParityReport {
        report_id: derived_id("cppe:authorship-parity", &seed)?,
        profile: CPPE_AUTHORSHIP_PARITY_ID.to_owned(),
        hand_candidate_ref: hand.candidate.candidate_id.clone(),
        model_candidate_ref: model.candidate.candidate_id.clone(),
        hand_projection_digest,
        model_projection_digest,
        axis_results,
        disposition,
        evidence_refs,
        residuals: BTreeSet::from([
            "parity proves equal treatment and observed behavior only".to_owned(),
            "model-shaped provenance grants no truth or authority".to_owned(),
            "no model or provider was invoked".to_owned(),
        ]),
        report_digest: empty_sha256(),
    };
    report.report_digest = compute_authorship_parity_report_digest(&report)?;
    Ok(report)
}

pub fn compute_authorship_parity_report_digest(
    report: &AuthorshipParityReport,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = report.clone();
    body.report_digest = empty_sha256();
    digest_serialized(&body, "authorship parity report")
}

fn validate_authorship_boundary(
    candidate: &ProcedureCandidate,
    template: &AuthorshipLaneTemplate,
) -> Result<(), EvaluationFault> {
    if template.authorship_evidence_refs.is_empty()
        || !template
            .authorship_evidence_refs
            .is_subset(&candidate.provenance_refs)
    {
        return Err(machine_fault(
            "authorship class requires explicit candidate provenance evidence",
        ));
    }
    let reserved = [
        template.validator_ref.as_str(),
        CPPE_COMPILER_ID,
        CPPE_VERIFIER_ID,
        CPPE_FAKE_OBSERVER_ID,
        CPPE_COORDINATOR_ID,
    ];
    if reserved
        .iter()
        .any(|principal| *principal == candidate.author_ref.as_str())
    {
        return Err(machine_fault(
            "candidate author cannot occupy validator compiler verifier Observer or coordinator authority",
        ));
    }
    if template.permitted_invocation_context.trim().is_empty()
        || template.session_purpose.trim().is_empty()
        || template.permitted_message_kinds.is_empty()
    {
        return Err(machine_fault(
            "authorship lane context, session purpose, and message permissions are required",
        ));
    }
    Ok(())
}

fn build_session(
    ir: &CantorProcessIr,
    admission: &AdmissionDisposition,
    template: &AuthorshipLaneTemplate,
) -> Result<NegotiationSession, EvaluationFault> {
    let required = ir
        .process_definitions
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let participants = ir
        .process_definitions
        .values()
        .map(|definition| {
            (
                definition.process_definition_id.clone(),
                Participant {
                    participant_id: definition.process_definition_id.clone(),
                    role_ref: definition.role_ref.clone(),
                    permitted_message_kinds: template.permitted_message_kinds.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let token_holder_ref = required
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| machine_fault("authorship lane has no process participant"))?;
    let frame = NegotiatedFrame {
        frame_id: template.frame_ref.clone(),
        generation: 1,
        propositions: BTreeMap::new(),
        conditions: template.frame_conditions.clone(),
        constraints: template.frame_constraints.clone(),
        evidence_refs: template.authorship_evidence_refs.clone(),
        objection_refs: BTreeSet::new(),
        participant_refs: required.clone(),
        policy_ref: admission.policy_ref.clone(),
    };
    Ok(NegotiationSession {
        session_generation_id: template.session_generation_ref.clone(),
        session_id: template.session_ref.clone(),
        frame_generation: 1,
        purpose: template.session_purpose.clone(),
        required_participant_refs: required,
        optional_observer_refs: BTreeSet::new(),
        participants,
        pinned_sop_anchor_refs: ir.sop_anchors.keys().cloned().collect(),
        policy_ref: admission.policy_ref.clone(),
        frame,
        token_holder_ref,
        pass_refs: BTreeSet::new(),
        message_frontier: BTreeSet::new(),
        status: NegotiationStatus::Opened,
    })
}

fn exact_schema_ref(
    schemas: &ProcedureSchemaSet,
    kind: crate::SchemaKind,
) -> Result<SemanticId, EvaluationFault> {
    let matches = schemas
        .schemas
        .values()
        .filter(|schema| schema.kind == kind)
        .map(|schema| schema.schema_id.clone())
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(machine_fault(
            "authorship lane requires exactly one input and output schema",
        ));
    }
    Ok(matches[0].clone())
}

pub(crate) fn validate_lane_evidence(lane: &AuthorshipLaneEvidence) -> Result<(), EvaluationFault> {
    if lane.authorship_evidence_refs.is_empty()
        || !lane
            .authorship_evidence_refs
            .is_subset(&lane.candidate.provenance_refs)
        || lane.validation.validator_ref == lane.candidate.author_ref
        || [
            CPPE_COMPILER_ID,
            CPPE_VERIFIER_ID,
            CPPE_FAKE_OBSERVER_ID,
            CPPE_COORDINATOR_ID,
        ]
        .contains(&lane.candidate.author_ref.as_str())
    {
        return Err(machine_fault(
            "authorship lane evidence violates provenance or authority separation",
        ));
    }
    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(lane.candidate.candidate_id.clone(), lane.candidate.clone());
    validate_procedure_forms(&forms)?;
    if compute_candidate_source_digest(&lane.candidate)? != lane.candidate.source_digest
        || lane.validation.candidate_ref != lane.candidate.candidate_id
        || lane.validation.candidate_source_digest != lane.candidate.source_digest
        || lane.validation.disposition != PhaseDisposition::Passed
        || compute_validation_receipt_digest(&lane.validation)? != lane.validation.receipt_digest
    {
        return Err(machine_fault(
            "authorship lane candidate or validation evidence is stale",
        ));
    }
    let compiled = compile_procedure_candidate(&lane.candidate, &lane.validation)?;
    if compiled.compilation_receipt != lane.compilation
        || compiled.process_ir.as_ref() != Some(&lane.ir)
        || compiled.compiled_procedure.as_ref() != Some(&lane.procedure)
        || compute_compilation_receipt_digest(&lane.compilation)? != lane.compilation.receipt_digest
    {
        return Err(machine_fault(
            "authorship lane compilation evidence does not replay exactly",
        ));
    }
    let verification = verify_compiled_procedure(
        &lane.candidate,
        &lane.validation,
        &lane.compilation,
        &lane.ir,
        &lane.procedure,
        &lane.recognized_anchors,
    )?;
    if verification != lane.verification
        || compute_verification_receipt_digest(&lane.verification)?
            != lane.verification.receipt_digest
    {
        return Err(machine_fault(
            "authorship lane verification evidence does not replay exactly",
        ));
    }
    let admission = fake_observer_admit(
        &lane.candidate,
        &lane.validation,
        &lane.compilation,
        &lane.ir,
        &lane.procedure,
        &lane.verification,
        &lane.policy,
    )?;
    if admission != lane.admission {
        return Err(machine_fault(
            "authorship lane admission evidence does not replay exactly",
        ));
    }
    let catalogue_transition = insert_admitted_procedure(
        &empty_procedure_catalogue()?,
        &lane.procedure,
        &lane.admission,
        lane.aliases.clone(),
    )?;
    if catalogue_transition.receipt != lane.catalogue_receipt
        || catalogue_transition.successor.as_ref() != Some(&lane.catalogue)
    {
        return Err(machine_fault(
            "authorship lane catalogue evidence does not replay exactly",
        ));
    }
    let coordination = coordinate_catalogued_procedure(
        &lane.catalogue,
        &lane.procedure,
        &lane.ir,
        &lane.admission,
        &lane.request,
        &lane.initial_session,
    )?;
    if coordination != lane.coordination {
        return Err(machine_fault(
            "authorship lane coordination evidence does not replay exactly",
        ));
    }
    let replay = verify_coordination_replay(
        &lane.catalogue,
        &lane.procedure,
        &lane.ir,
        &lane.admission,
        &lane.request,
        &lane.initial_session,
    )?;
    if replay != lane.replay || !replay.matched {
        return Err(machine_fault(
            "authorship lane replay receipt does not replay exactly",
        ));
    }
    let mut session = coordination
        .session_successor
        .clone()
        .ok_or_else(|| machine_fault("authorship coordination omitted session successor"))?;
    let mut known = BTreeMap::new();
    for pass in ordered_passes(&lane.token_passes)? {
        let transition = record_token_ring_pass(
            &session,
            &known,
            &session.token_holder_ref,
            pass.logical_time,
        )?;
        if transition.pass != *pass {
            return Err(machine_fault(
                "authorship token pass evidence does not replay exactly",
            ));
        }
        known.insert(pass.pass_id.clone(), pass.clone());
        session = transition.successor;
    }
    if session != lane.stable_session
        || session.status != NegotiationStatus::StableCandidate
        || session.pass_refs != lane.token_passes.keys().cloned().collect()
    {
        return Err(machine_fault(
            "authorship stable-session evidence does not replay exactly",
        ));
    }
    Ok(())
}

fn behavior_projection(
    lane: &AuthorshipLaneEvidence,
) -> Result<AuthorshipBehaviorProjection, EvaluationFault> {
    validate_lane_evidence(lane)?;
    let normalized_source_form = lane
        .candidate
        .normalized_source_form
        .clone()
        .ok_or_else(|| machine_fault("authorship lane lacks normalized source form"))?;
    let process_definition_digest =
        digest_serialized(&lane.candidate.process_definitions, "process definitions")?;
    let mut messages = lane
        .coordination
        .messages
        .values()
        .map(|message| {
            Ok(BehaviorMessageProjection {
                sender_ref: message.sender_ref.clone(),
                receiver_ref: message.receiver_ref.clone(),
                frame_generation: message.frame_generation,
                kind: message.kind,
                payload_digest: digest_serialized(&message.payload, "message payload")?,
                logical_time: message.logical_time,
                expires_at_logical_time: message.expires_at_logical_time,
                causal_predecessor_count: message.causal_predecessor_refs.len() as u64,
            })
        })
        .collect::<Result<Vec<_>, EvaluationFault>>()?;
    messages.sort_by(|left, right| {
        (
            left.logical_time,
            &left.sender_ref,
            &left.receiver_ref,
            left.kind,
        )
            .cmp(&(
                right.logical_time,
                &right.sender_ref,
                &right.receiver_ref,
                right.kind,
            ))
    });
    let mut continuations = lane
        .coordination
        .continuations
        .values()
        .map(|continuation| {
            let state = &continuation.process_state;
            Ok(BehaviorContinuationProjection {
                definition_ref: state.definition_ref.clone(),
                generation: state.generation,
                region_ref: state.region_ref.clone(),
                instruction_index: state.instruction_index,
                lifecycle: state.lifecycle,
                awaited_shape: awaited_shape(&state.awaited_condition),
                local_state_digest: digest_serialized(&state.local_state, "local state")?,
                logical_time: state.logical_time,
            })
        })
        .collect::<Result<Vec<_>, EvaluationFault>>()?;
    continuations.sort_by(|left, right| {
        (&left.definition_ref, left.generation).cmp(&(&right.definition_ref, right.generation))
    });
    let token_participant_order = ordered_passes(&lane.token_passes)?
        .into_iter()
        .map(|pass| pass.participant_ref.clone())
        .collect();
    Ok(AuthorshipBehaviorProjection {
        purpose: lane.candidate.purpose.clone(),
        scope: lane.candidate.scope.clone(),
        language_profile: lane.candidate.language_profile.clone(),
        source_digest: lane.candidate.source_digest.clone(),
        normalized_source_form,
        schema_set_digest: lane.candidate.schema_set.schema_set_digest.clone(),
        process_definition_digest,
        effect_declaration_digest: compute_effect_declaration_digest(&lane.candidate.effects)?,
        bounds_digest: compute_procedure_bounds_digest(&lane.candidate.bounds)?,
        sensitivity: lane.candidate.sensitivity,
        retention_policy_ref: lane.candidate.retention_policy_ref.clone(),
        compilation_cost: lane.compilation.cost_estimate.clone(),
        pipeline_principals: vec![
            lane.validation.validator_ref.clone(),
            lane.compilation.compiler_ref.clone(),
            lane.verification.verifier_ref.clone(),
            lane.admission.observer_ref.clone(),
            lane.catalogue_receipt.principal_ref.clone(),
            lane.replay.coordinator_ref.clone(),
        ],
        phase_dispositions: vec![
            lane.validation.disposition,
            lane.compilation.disposition,
            lane.verification.disposition,
            lane.catalogue_receipt.disposition,
        ],
        admission_decision: lane.admission.decision,
        permitted_invocation_contexts: lane.admission.permitted_invocation_contexts.clone(),
        revocation_conditions: lane.admission.revocation_conditions.clone(),
        invocation_disposition: lane.coordination.result.disposition,
        output: lane.coordination.result.output.clone(),
        consumed_budget: lane.coordination.result.consumed_budget.clone(),
        residuals: lane.coordination.result.residuals.clone(),
        trace: lane
            .coordination
            .result
            .semantic_trace
            .events
            .iter()
            .map(|event| BehaviorTraceProjection {
                kind: event.kind,
                subject_generation: event.subject_generation,
                payload_digest: event.normalized_payload_digest.clone(),
                causal_predecessor_count: event.causal_predecessor_refs.len() as u64,
            })
            .collect(),
        steps: lane
            .coordination
            .steps
            .iter()
            .map(|step| BehaviorStepProjection {
                instruction_ref: step.instruction_ref.clone(),
                input_generation: step.input_generation,
                input_message_count: step.input_message_refs.len() as u64,
                emitted_message_count: step.emitted_message_refs.len() as u64,
                returned_value: step.returned_value.clone(),
                faulted: step.fault_ref.is_some(),
                logical_time_before: step.logical_time_before,
                logical_time_after: step.logical_time_after,
                consumed_budget: step.consumed_budget.clone(),
            })
            .collect(),
        messages,
        continuations,
        active_continuation_count: lane.coordination.active_continuation_refs.len() as u64,
        token_participant_order,
        stable_status: lane.stable_session.status,
        stable_frame_generation: lane.stable_session.frame_generation,
        replay_matched: lane.replay.matched,
    })
}

fn awaited_shape(condition: &crate::AwaitedCondition) -> String {
    match condition {
        crate::AwaitedCondition::None => "none".to_owned(),
        crate::AwaitedCondition::Message { tag } => format!("message:{tag}"),
        crate::AwaitedCondition::LogicalTime { not_before } => {
            format!("logical_time:{not_before}")
        }
        crate::AwaitedCondition::ProcessTerminal { .. } => "process_terminal:1".to_owned(),
        crate::AwaitedCondition::Join {
            required_process_refs,
        } => format!("join:{}", required_process_refs.len()),
    }
}

fn ordered_passes(
    passes: &BTreeMap<SemanticId, TokenRingPass>,
) -> Result<Vec<&TokenRingPass>, EvaluationFault> {
    let mut result = Vec::new();
    let mut predecessor = None;
    while result.len() < passes.len() {
        let next = passes
            .values()
            .find(|pass| pass.predecessor_pass_ref == predecessor)
            .ok_or_else(|| machine_fault("token pass evidence is not one exact chain"))?;
        if result
            .iter()
            .any(|seen: &&TokenRingPass| seen.pass_id == next.pass_id)
        {
            return Err(machine_fault("token pass evidence contains a cycle"));
        }
        predecessor = Some(next.pass_id.clone());
        result.push(next);
    }
    Ok(result)
}
