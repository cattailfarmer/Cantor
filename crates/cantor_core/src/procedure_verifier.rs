//! Independent static verification and fake Observer admission for CPPE-I04.
//!
//! This module checks exact upstream identities and independently inspects the
//! normalized Process IR. It constructs immutable receipts only. It does not
//! catalogue, schedule, interpret, invoke, persist, call a provider, or perform
//! an external effect.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    AdmissionDecision, AdmissionDisposition, CPPE_COMPILER_ID, CPPE_FORM_VERSION, CPPE_IR_VERSION,
    CantorProcessIr, CompilationReceipt, CompiledProcedureIdentity, ContentDigest, EvaluationFault,
    PhaseDisposition, ProcedureBounds, ProcedureCandidate, ProcedureEffectClass,
    ProcedureEffectDeclaration, ProcedureFormSet, ProcedureType, ReceiptEvidence, SemanticId,
    SopAnchorBinding, ValidationReceipt, VerificationReceipt, compute_compilation_receipt_digest,
    compute_compiled_procedure_digest, compute_process_ir_digest,
    compute_validation_receipt_digest, from_normalized_process_ir, sha256_bytes,
    to_normalized_process_ir, validate_procedure_forms,
};

pub const CPPE_VERIFIER_ID: &str = "cantor-process-verifier/0.1";
pub const CPPE_FAKE_OBSERVER_ID: &str = "cantor-fake-observer/0.1";
pub const CPPE_ADMISSION_POLICY_VERSION: &str = "cantor-fake-admission-policy/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeObserverAdmissionPolicy {
    pub policy_ref: SemanticId,
    pub policy_version: String,
    pub observer_ref: SemanticId,
    pub required_verifier_ref: SemanticId,
    pub required_compiler_ref: SemanticId,
    pub candidate_ref: SemanticId,
    pub candidate_source_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub procedure_ref: SemanticId,
    pub procedure_digest: ContentDigest,
    pub anchor_set_digest: ContentDigest,
    pub effect_declaration_digest: ContentDigest,
    pub bound_set_ref: SemanticId,
    pub bounds_digest: ContentDigest,
    pub decision: AdmissionDecision,
    pub permitted_invocation_contexts: BTreeSet<String>,
    pub revocation_conditions: BTreeSet<String>,
    pub policy_digest: ContentDigest,
}

pub fn verify_compiled_procedure(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    process_ir: &CantorProcessIr,
    compiled_procedure: &CompiledProcedureIdentity,
    recognized_anchors: &BTreeMap<SemanticId, SopAnchorBinding>,
) -> Result<VerificationReceipt, EvaluationFault> {
    let verifier_ref = SemanticId::new(CPPE_VERIFIER_ID)?;
    let attempt_digest = verification_attempt_digest(
        candidate,
        validation_receipt,
        compilation_receipt,
        process_ir,
        compiled_procedure,
        recognized_anchors,
        &verifier_ref,
    )?;
    let anchor_set_digest = compute_anchor_set_digest(&process_ir.sop_anchors)?;
    let effect_declaration_digest = compute_effect_declaration_digest(&process_ir.effects)?;
    let bounds_digest = compute_procedure_bounds_digest(&process_ir.bounds)?;

    let verification = inspect_compiled_procedure(
        candidate,
        validation_receipt,
        compilation_receipt,
        process_ir,
        compiled_procedure,
        recognized_anchors,
    );
    let (disposition, diagnostics, residuals) = match verification {
        Ok(diagnostics) => (
            PhaseDisposition::Passed,
            diagnostics,
            BTreeSet::from([
                "Observer admission not performed".to_owned(),
                "catalogue insertion and invocation not performed".to_owned(),
            ]),
        ),
        Err(fault) => (
            PhaseDisposition::Refused,
            BTreeSet::from([fault.message]),
            BTreeSet::from([
                "compiled candidate preserved without verification authority".to_owned(),
                "Observer admission not entered".to_owned(),
            ]),
        ),
    };

    let mut receipt = VerificationReceipt {
        receipt_id: derived_id("cppe:verification-receipt", &attempt_digest)?,
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        compilation_receipt_ref: compilation_receipt.receipt_id.clone(),
        verifier_ref,
        compiler_ref: process_ir.compiler_ref.clone(),
        ir_ref: process_ir.ir_id.clone(),
        ir_digest: process_ir.ir_digest.clone(),
        compiled_procedure_ref: compiled_procedure.procedure_id.clone(),
        compiled_procedure_digest: compiled_procedure.procedure_digest.clone(),
        anchor_set_digest,
        effect_declaration_digest,
        bound_set_ref: process_ir.bounds.bound_set_id.clone(),
        bounds_digest,
        disposition,
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([
                validation_receipt.receipt_id.clone(),
                compilation_receipt.receipt_id.clone(),
                process_ir.ir_id.clone(),
                compiled_procedure.procedure_id.clone(),
            ]),
            residuals,
            diagnostics,
        },
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = compute_verification_receipt_digest(&receipt)?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
pub fn build_fake_observer_policy(
    policy_ref: SemanticId,
    candidate: &ProcedureCandidate,
    process_ir: &CantorProcessIr,
    compiled_procedure: &CompiledProcedureIdentity,
    decision: AdmissionDecision,
    permitted_invocation_contexts: BTreeSet<String>,
    revocation_conditions: BTreeSet<String>,
) -> Result<FakeObserverAdmissionPolicy, EvaluationFault> {
    let mut policy = FakeObserverAdmissionPolicy {
        policy_ref,
        policy_version: CPPE_ADMISSION_POLICY_VERSION.to_owned(),
        observer_ref: SemanticId::new(CPPE_FAKE_OBSERVER_ID)?,
        required_verifier_ref: SemanticId::new(CPPE_VERIFIER_ID)?,
        required_compiler_ref: SemanticId::new(CPPE_COMPILER_ID)?,
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        ir_ref: process_ir.ir_id.clone(),
        ir_digest: process_ir.ir_digest.clone(),
        procedure_ref: compiled_procedure.procedure_id.clone(),
        procedure_digest: compiled_procedure.procedure_digest.clone(),
        anchor_set_digest: compute_anchor_set_digest(&process_ir.sop_anchors)?,
        effect_declaration_digest: compute_effect_declaration_digest(&process_ir.effects)?,
        bound_set_ref: process_ir.bounds.bound_set_id.clone(),
        bounds_digest: compute_procedure_bounds_digest(&process_ir.bounds)?,
        decision,
        permitted_invocation_contexts,
        revocation_conditions,
        policy_digest: empty_sha256(),
    };
    policy.policy_digest = compute_fake_observer_policy_digest(&policy)?;
    Ok(policy)
}

#[allow(clippy::too_many_arguments)]
pub fn fake_observer_admit(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    process_ir: &CantorProcessIr,
    compiled_procedure: &CompiledProcedureIdentity,
    verification_receipt: &VerificationReceipt,
    policy: &FakeObserverAdmissionPolicy,
) -> Result<AdmissionDisposition, EvaluationFault> {
    let attempt_digest = admission_attempt_digest(
        candidate,
        validation_receipt,
        compilation_receipt,
        process_ir,
        compiled_procedure,
        verification_receipt,
        policy,
    )?;
    let admission = inspect_admission_lineage(
        candidate,
        validation_receipt,
        compilation_receipt,
        process_ir,
        compiled_procedure,
        verification_receipt,
        policy,
    );
    let (decision, contexts, revocations, diagnostics, residuals) = match admission {
        Ok(()) if policy.decision == AdmissionDecision::Refuse => (
            AdmissionDecision::Refuse,
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::from(["exact procedure was explicitly refused by policy".to_owned()]),
            BTreeSet::from([
                "no invocation authority granted".to_owned(),
                "catalogue and invocation not entered".to_owned(),
            ]),
        ),
        Ok(()) => (
            policy.decision,
            policy.permitted_invocation_contexts.clone(),
            policy.revocation_conditions.clone(),
            BTreeSet::from(["exact bounded procedure admitted by fake Observer".to_owned()]),
            BTreeSet::from([
                "catalogue insertion not performed".to_owned(),
                "invocation and effects not performed".to_owned(),
            ]),
        ),
        Err(fault) => (
            AdmissionDecision::Refuse,
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::from([fault.message]),
            BTreeSet::from([
                "compiled candidate and all predecessor receipts preserved".to_owned(),
                "catalogue and invocation not entered".to_owned(),
            ]),
        ),
    };

    let mut disposition = AdmissionDisposition {
        disposition_id: derived_id("cppe:admission-disposition", &attempt_digest)?,
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        validation_receipt_ref: validation_receipt.receipt_id.clone(),
        compilation_receipt_ref: compilation_receipt.receipt_id.clone(),
        verification_receipt_ref: verification_receipt.receipt_id.clone(),
        observer_ref: policy.observer_ref.clone(),
        compiler_ref: process_ir.compiler_ref.clone(),
        ir_ref: process_ir.ir_id.clone(),
        ir_digest: process_ir.ir_digest.clone(),
        procedure_ref: compiled_procedure.procedure_id.clone(),
        procedure_digest: compiled_procedure.procedure_digest.clone(),
        anchor_set_digest: compute_anchor_set_digest(&process_ir.sop_anchors)?,
        effect_declaration_digest: compute_effect_declaration_digest(&process_ir.effects)?,
        bound_set_ref: process_ir.bounds.bound_set_id.clone(),
        bounds_digest: compute_procedure_bounds_digest(&process_ir.bounds)?,
        decision,
        permitted_invocation_contexts: contexts,
        revocation_conditions: revocations,
        policy_ref: policy.policy_ref.clone(),
        policy_digest: policy.policy_digest.clone(),
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([
                validation_receipt.receipt_id.clone(),
                compilation_receipt.receipt_id.clone(),
                verification_receipt.receipt_id.clone(),
                process_ir.ir_id.clone(),
                compiled_procedure.procedure_id.clone(),
                policy.policy_ref.clone(),
            ]),
            residuals,
            diagnostics,
        },
        disposition_digest: empty_sha256(),
    };
    disposition.disposition_digest = compute_admission_disposition_digest(&disposition)?;
    Ok(disposition)
}

pub fn compute_verification_receipt_digest(
    receipt: &VerificationReceipt,
) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = receipt.clone();
    digest_body.receipt_digest = empty_sha256();
    digest_serialized(&digest_body, "verification receipt")
}

pub fn compute_admission_disposition_digest(
    disposition: &AdmissionDisposition,
) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = disposition.clone();
    digest_body.disposition_digest = empty_sha256();
    digest_serialized(&digest_body, "admission disposition")
}

pub fn compute_fake_observer_policy_digest(
    policy: &FakeObserverAdmissionPolicy,
) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = policy.clone();
    digest_body.policy_digest = empty_sha256();
    digest_serialized(&digest_body, "fake Observer admission policy")
}

pub fn compute_anchor_set_digest(
    anchors: &BTreeMap<SemanticId, SopAnchorBinding>,
) -> Result<ContentDigest, EvaluationFault> {
    digest_serialized(anchors, "SOP anchor set")
}

pub fn compute_effect_declaration_digest(
    effects: &ProcedureEffectDeclaration,
) -> Result<ContentDigest, EvaluationFault> {
    digest_serialized(effects, "effect declaration")
}

pub fn compute_procedure_bounds_digest(
    bounds: &ProcedureBounds,
) -> Result<ContentDigest, EvaluationFault> {
    digest_serialized(bounds, "procedure bounds")
}

fn inspect_compiled_procedure(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    process_ir: &CantorProcessIr,
    compiled_procedure: &CompiledProcedureIdentity,
    recognized_anchors: &BTreeMap<SemanticId, SopAnchorBinding>,
) -> Result<BTreeSet<String>, EvaluationFault> {
    validate_predecessor_lineage(
        candidate,
        validation_receipt,
        compilation_receipt,
        process_ir,
        compiled_procedure,
    )?;
    verify_compiler_derivations(
        candidate,
        validation_receipt,
        compilation_receipt,
        process_ir,
        compiled_procedure,
    )?;

    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(candidate.candidate_id.clone(), candidate.clone());
    forms
        .process_irs
        .insert(process_ir.ir_id.clone(), process_ir.clone());
    forms.compiled_procedures.insert(
        compiled_procedure.procedure_id.clone(),
        compiled_procedure.clone(),
    );
    forms.validation_receipts.insert(
        validation_receipt.receipt_id.clone(),
        validation_receipt.clone(),
    );
    forms.compilation_receipts.insert(
        compilation_receipt.receipt_id.clone(),
        compilation_receipt.clone(),
    );
    validate_procedure_forms(&forms)?;

    verify_schema_and_type_closure(process_ir)?;
    verify_effect_wall(process_ir)?;
    verify_anchor_set(process_ir, recognized_anchors)?;
    verify_process_graphs(process_ir)?;
    verify_source_map(process_ir)?;
    let normalized = to_normalized_process_ir(process_ir)?;
    if from_normalized_process_ir(&normalized)? != *process_ir {
        return Err(machine_fault(
            "normalized Process IR replay changed content",
        ));
    }

    Ok(BTreeSet::from([
        "exact candidate, validation, compilation, IR, and procedure lineage passed".to_owned(),
        "type and schema closure passed".to_owned(),
        "termination and resource-bound inspection passed".to_owned(),
        "effectless and prohibited-operation wall passed".to_owned(),
        "recognized SOP anchor inspection passed".to_owned(),
        "lifecycle and deterministic graph inspection passed".to_owned(),
        "complete source-map inspection passed".to_owned(),
        "normalized IR replay passed".to_owned(),
    ]))
}

fn validate_predecessor_lineage(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    process_ir: &CantorProcessIr,
    compiled_procedure: &CompiledProcedureIdentity,
) -> Result<(), EvaluationFault> {
    if validation_receipt.disposition != PhaseDisposition::Passed
        || validation_receipt.candidate_ref != candidate.candidate_id
        || validation_receipt.candidate_source_digest != candidate.source_digest
        || compute_validation_receipt_digest(validation_receipt)?
            != validation_receipt.receipt_digest
    {
        return Err(machine_fault(
            "verification requires exact passed validation evidence",
        ));
    }
    if compilation_receipt.disposition != PhaseDisposition::Passed
        || compilation_receipt.candidate_ref != candidate.candidate_id
        || compilation_receipt.candidate_source_digest != candidate.source_digest
        || compilation_receipt.validation_receipt_ref != validation_receipt.receipt_id
        || compilation_receipt.compiler_ref != process_ir.compiler_ref
        || compilation_receipt.ir_ref.as_ref() != Some(&process_ir.ir_id)
        || compilation_receipt.ir_digest.as_ref() != Some(&process_ir.ir_digest)
        || compute_compilation_receipt_digest(compilation_receipt)?
            != compilation_receipt.receipt_digest
    {
        return Err(machine_fault(
            "verification requires exact passed compilation evidence",
        ));
    }
    let compiler_ref = SemanticId::new(CPPE_COMPILER_ID)?;
    if process_ir.compiler_ref != compiler_ref
        || compute_process_ir_digest(process_ir)? != process_ir.ir_digest
    {
        return Err(machine_fault(
            "Process IR compiler or digest identity is invalid",
        ));
    }
    if compiled_procedure.candidate_ref != candidate.candidate_id
        || compiled_procedure.canonical_source_digest != candidate.source_digest
        || compiled_procedure.compiler_ref != process_ir.compiler_ref
        || compiled_procedure.ir_ref != process_ir.ir_id
        || compiled_procedure.ir_digest != process_ir.ir_digest
        || compiled_procedure.schema_set_digest != process_ir.schema_set.schema_set_digest
        || compiled_procedure.effect_class != process_ir.effects.effect_class
        || compiled_procedure.bound_set_ref != process_ir.bounds.bound_set_id
        || compute_compiled_procedure_digest(compiled_procedure)?
            != compiled_procedure.procedure_digest
    {
        return Err(machine_fault(
            "compiled procedure identity does not bind exact IR content",
        ));
    }
    Ok(())
}

fn verify_compiler_derivations(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    ir: &CantorProcessIr,
    procedure: &CompiledProcedureIdentity,
) -> Result<(), EvaluationFault> {
    let compiler_ref = SemanticId::new(CPPE_COMPILER_ID)?;
    let attempt_digest = digest_serialized(
        &(
            &candidate.candidate_id,
            &candidate.source_digest,
            &validation_receipt.receipt_id,
            &validation_receipt.receipt_digest,
            &compiler_ref,
            CPPE_FORM_VERSION,
            CPPE_IR_VERSION,
        ),
        "independent compiler attempt",
    )?;
    if ir.ir_id != derived_id("cppe:ir", &attempt_digest)? {
        return Err(machine_fault(
            "Process IR identity is not the deterministic compiler identity",
        ));
    }
    if ir.source_digest != candidate.source_digest
        || ir.schema_set != candidate.schema_set
        || ir.sop_anchors != candidate.sop_anchors
        || ir.process_definitions != candidate.process_definitions
        || ir.effects != candidate.effects
        || ir.bounds != candidate.bounds
    {
        return Err(machine_fault(
            "Process IR is not the exact deterministic lowering of its candidate",
        ));
    }
    if procedure.procedure_version != "0.1"
        || procedure.language_profile != CPPE_FORM_VERSION
        || !procedure.predecessor_procedure_refs.is_empty()
    {
        return Err(machine_fault(
            "compiled procedure uses an unsupported version, profile, or predecessor set",
        ));
    }

    let procedure_seed = digest_serialized(
        &(
            &candidate.candidate_id,
            &candidate.source_digest,
            &compiler_ref,
            &ir.ir_id,
            &ir.ir_digest,
        ),
        "independent procedure identity",
    )?;
    if procedure.procedure_id != derived_id("cppe:procedure", &procedure_seed)? {
        return Err(machine_fault(
            "compiled procedure identity is not the deterministic compiler identity",
        ));
    }

    let region_count = candidate
        .process_definitions
        .values()
        .map(|process| process.control_regions.len() as u64)
        .sum();
    let instruction_count = candidate
        .process_definitions
        .values()
        .flat_map(|process| process.control_regions.values())
        .map(|region| region.instructions.len() as u64)
        .sum();
    let expected_cost = BTreeMap::from([
        (
            "anchor_count".to_owned(),
            candidate.sop_anchors.len() as u64,
        ),
        ("instruction_count".to_owned(), instruction_count),
        (
            "process_count".to_owned(),
            candidate.process_definitions.len() as u64,
        ),
        ("region_count".to_owned(), region_count),
        (
            "schema_count".to_owned(),
            candidate.schema_set.schemas.len() as u64,
        ),
        ("source_map_count".to_owned(), ir.source_map.len() as u64),
        ("type_count".to_owned(), ir.type_table.len() as u64),
    ]);
    if compilation_receipt.cost_estimate != expected_cost {
        return Err(machine_fault(
            "compilation cost estimate is not reproducible",
        ));
    }
    Ok(())
}

fn verify_schema_and_type_closure(ir: &CantorProcessIr) -> Result<(), EvaluationFault> {
    let mut expected_type_table = BTreeMap::new();
    for schema in ir.schema_set.schemas.values() {
        for field in schema.fields.values() {
            verify_type_reference(&field.value_type, ir)?;
            expected_type_table.insert(
                format!("{}.field.{}", schema.schema_id, field.field_name),
                field.value_type.clone(),
            );
        }
        for variant in schema.tagged_variants.values() {
            verify_type_reference(&variant.value_type, ir)?;
            expected_type_table.insert(
                format!("{}.variant.{}", schema.schema_id, variant.tag),
                variant.value_type.clone(),
            );
        }
    }
    if ir.type_table != expected_type_table {
        return Err(machine_fault(
            "Process IR type table is not the exact schema closure",
        ));
    }
    if !ir.constants.is_empty() {
        return Err(machine_fault(
            "first compiler profile does not authorize an IR constant table",
        ));
    }
    Ok(())
}

fn verify_type_reference(
    value_type: &ProcedureType,
    ir: &CantorProcessIr,
) -> Result<(), EvaluationFault> {
    match value_type {
        ProcedureType::List { member, .. } => verify_type_reference(member, ir),
        ProcedureType::OrderedMap { value, .. } => verify_type_reference(value, ir),
        ProcedureType::Record { schema_ref }
        | ProcedureType::TaggedUnion { schema_ref }
        | ProcedureType::TypedFault { schema_ref } => {
            if ir.schema_set.schemas.contains_key(schema_ref) {
                Ok(())
            } else {
                Err(machine_fault(format!(
                    "procedure type references missing schema {schema_ref}"
                )))
            }
        }
        _ => Ok(()),
    }
}

fn verify_effect_wall(ir: &CantorProcessIr) -> Result<(), EvaluationFault> {
    use crate::ProhibitedProcedureOperation::*;
    let all_prohibited = BTreeSet::from([
        Recursion,
        UnboundedIteration,
        UnrestrictedInheritance,
        DynamicAllocation,
        PointerAccess,
        NativeStackCapture,
        SelfModification,
        RuntimeCodeLoading,
        ExecutableReflection,
        UndeclaredStorage,
        SystemClock,
        Randomness,
        Environment,
        Filesystem,
        Network,
        Database,
        Subprocess,
        Provider,
        Notification,
        Git,
        Model,
        UnsafeCode,
        Device,
        ExternalEffect,
    ]);
    if ir.effects.effect_class != ProcedureEffectClass::Effectless
        || ir.effects.prohibited_operations != all_prohibited
    {
        return Err(machine_fault(
            "Process IR does not retain the complete effectless wall",
        ));
    }
    Ok(())
}

fn verify_anchor_set(
    ir: &CantorProcessIr,
    recognized_anchors: &BTreeMap<SemanticId, SopAnchorBinding>,
) -> Result<(), EvaluationFault> {
    for (anchor_id, anchor) in &ir.sop_anchors {
        if !recognized_anchors
            .get(anchor_id)
            .is_some_and(|recognized| recognized == anchor)
        {
            return Err(machine_fault(format!(
                "SOP anchor {anchor_id} is missing, stale, or substituted"
            )));
        }
    }
    Ok(())
}

fn verify_process_graphs(ir: &CantorProcessIr) -> Result<(), EvaluationFault> {
    let mut instruction_ids = BTreeSet::new();
    for process in ir.process_definitions.values() {
        if process.resource_contribution_ref != ir.bounds.bound_set_id {
            return Err(machine_fault(
                "process does not cite the active resource bound set",
            ));
        }
        let declared_terminals = process
            .control_regions
            .values()
            .filter(|region| region.terminal)
            .map(|region| region.region_id.clone())
            .collect::<BTreeSet<_>>();
        if declared_terminals.is_empty() || declared_terminals != process.terminal_region_refs {
            return Err(machine_fault(
                "process terminal-region declaration is incomplete",
            ));
        }
        for region in process.control_regions.values() {
            let final_instruction = region
                .instructions
                .last()
                .ok_or_else(|| machine_fault("control region cannot be empty"))?;
            if region.terminal {
                if !matches!(
                    final_instruction.operation,
                    crate::ProcessOperation::Return | crate::ProcessOperation::Fault
                ) || !final_instruction.successor_region_refs.is_empty()
                {
                    return Err(machine_fault(
                        "terminal region must end in return or fault without a successor",
                    ));
                }
            } else if matches!(
                final_instruction.operation,
                crate::ProcessOperation::Return | crate::ProcessOperation::Fault
            ) {
                return Err(machine_fault(
                    "nonterminal region cannot end in return or fault",
                ));
            }
        }

        let mut reachable = BTreeSet::new();
        let mut frontier = VecDeque::from([process.entry_region_ref.clone()]);
        while let Some(region_ref) = frontier.pop_front() {
            if !reachable.insert(region_ref.clone()) {
                continue;
            }
            let region = process
                .control_regions
                .get(&region_ref)
                .ok_or_else(|| machine_fault("process graph references a missing region"))?;
            for instruction in &region.instructions {
                if !instruction_ids.insert(instruction.instruction_id.clone()) {
                    return Err(machine_fault("Process IR repeats an instruction identity"));
                }
                let unique_successors = instruction
                    .successor_region_refs
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                if unique_successors.len() != instruction.successor_region_refs.len() {
                    return Err(machine_fault("instruction repeats a successor region"));
                }
                frontier.extend(unique_successors);
            }
        }
        if reachable.len() != process.control_regions.len() {
            return Err(machine_fault(
                "process contains an unreachable control region",
            ));
        }

        let mut can_terminate = declared_terminals.clone();
        loop {
            let before = can_terminate.len();
            for region in process.control_regions.values() {
                if region.instructions.iter().any(|instruction| {
                    instruction
                        .successor_region_refs
                        .iter()
                        .any(|successor| can_terminate.contains(successor))
                }) {
                    can_terminate.insert(region.region_id.clone());
                }
            }
            if can_terminate.len() == before {
                break;
            }
        }
        if !reachable.is_subset(&can_terminate) {
            return Err(machine_fault(
                "process graph contains a region with no path to a terminal region",
            ));
        }
    }
    Ok(())
}

fn verify_source_map(ir: &CantorProcessIr) -> Result<(), EvaluationFault> {
    let mut expected = BTreeMap::new();
    for process in ir.process_definitions.values() {
        for region in process.control_regions.values() {
            for instruction in &region.instructions {
                let seed = digest_serialized(
                    &(
                        &ir.source_digest,
                        &process.process_definition_id,
                        &region.region_id,
                        &instruction.instruction_id,
                        &instruction.source_span_ref,
                    ),
                    "independent source-map identity",
                )?;
                let source_map_id = derived_id("cppe:source-map", &seed)?;
                if expected
                    .insert(
                        instruction.instruction_id.clone(),
                        (instruction.source_span_ref.clone(), source_map_id),
                    )
                    .is_some()
                {
                    return Err(machine_fault(
                        "source map input repeats an instruction identity",
                    ));
                }
            }
        }
    }
    if ir.source_map.len() != expected.len() {
        return Err(machine_fault(
            "source map does not cover every instruction exactly once",
        ));
    }
    let mut mapped = BTreeSet::new();
    for entry in ir.source_map.values() {
        if !mapped.insert(entry.ir_subject_ref.clone())
            || !expected.get(&entry.ir_subject_ref).is_some_and(
                |(source_span_ref, source_map_id)| {
                    source_span_ref == &entry.source_span_ref
                        && source_map_id == &entry.source_map_id
                },
            )
        {
            return Err(machine_fault(
                "source map contains a missing, duplicate, or substituted entry",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn inspect_admission_lineage(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    process_ir: &CantorProcessIr,
    compiled_procedure: &CompiledProcedureIdentity,
    verification_receipt: &VerificationReceipt,
    policy: &FakeObserverAdmissionPolicy,
) -> Result<(), EvaluationFault> {
    validate_predecessor_lineage(
        candidate,
        validation_receipt,
        compilation_receipt,
        process_ir,
        compiled_procedure,
    )?;
    if verification_receipt.disposition != PhaseDisposition::Passed
        || compute_verification_receipt_digest(verification_receipt)?
            != verification_receipt.receipt_digest
        || verification_receipt.candidate_ref != candidate.candidate_id
        || verification_receipt.candidate_source_digest != candidate.source_digest
        || verification_receipt.compilation_receipt_ref != compilation_receipt.receipt_id
        || verification_receipt.verifier_ref != policy.required_verifier_ref
        || verification_receipt.compiler_ref != process_ir.compiler_ref
        || verification_receipt.ir_ref != process_ir.ir_id
        || verification_receipt.ir_digest != process_ir.ir_digest
        || verification_receipt.compiled_procedure_ref != compiled_procedure.procedure_id
        || verification_receipt.compiled_procedure_digest != compiled_procedure.procedure_digest
        || verification_receipt.anchor_set_digest
            != compute_anchor_set_digest(&process_ir.sop_anchors)?
        || verification_receipt.effect_declaration_digest
            != compute_effect_declaration_digest(&process_ir.effects)?
        || verification_receipt.bound_set_ref != process_ir.bounds.bound_set_id
        || verification_receipt.bounds_digest
            != compute_procedure_bounds_digest(&process_ir.bounds)?
    {
        return Err(machine_fault(
            "Observer requires exact passed verification evidence",
        ));
    }
    if policy.policy_version != CPPE_ADMISSION_POLICY_VERSION
        || policy.observer_ref != SemanticId::new(CPPE_FAKE_OBSERVER_ID)?
        || policy.required_compiler_ref != process_ir.compiler_ref
        || policy.candidate_ref != candidate.candidate_id
        || policy.candidate_source_digest != candidate.source_digest
        || policy.ir_ref != process_ir.ir_id
        || policy.ir_digest != process_ir.ir_digest
        || policy.procedure_ref != compiled_procedure.procedure_id
        || policy.procedure_digest != compiled_procedure.procedure_digest
        || policy.anchor_set_digest != compute_anchor_set_digest(&process_ir.sop_anchors)?
        || policy.effect_declaration_digest
            != compute_effect_declaration_digest(&process_ir.effects)?
        || policy.bound_set_ref != process_ir.bounds.bound_set_id
        || policy.bounds_digest != compute_procedure_bounds_digest(&process_ir.bounds)?
        || compute_fake_observer_policy_digest(policy)? != policy.policy_digest
    {
        return Err(machine_fault(
            "fake Observer policy does not bind the exact procedure",
        ));
    }
    if policy.decision != AdmissionDecision::Refuse
        && (policy.permitted_invocation_contexts.is_empty()
            || policy.revocation_conditions.is_empty())
    {
        return Err(machine_fault(
            "admission policy must name invocation context and revocation conditions",
        ));
    }
    for value in policy
        .permitted_invocation_contexts
        .iter()
        .chain(policy.revocation_conditions.iter())
    {
        if value.trim().is_empty() || value.len() as u64 > process_ir.bounds.maximum_text_bytes {
            return Err(machine_fault(
                "admission context or revocation condition is blank or over bound",
            ));
        }
    }
    Ok(())
}

fn verification_attempt_digest(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    ir: &CantorProcessIr,
    procedure: &CompiledProcedureIdentity,
    recognized_anchors: &BTreeMap<SemanticId, SopAnchorBinding>,
    verifier_ref: &SemanticId,
) -> Result<ContentDigest, EvaluationFault> {
    digest_serialized(
        &(
            &candidate.candidate_id,
            &candidate.source_digest,
            &validation_receipt.receipt_id,
            &validation_receipt.receipt_digest,
            &compilation_receipt.receipt_id,
            &compilation_receipt.receipt_digest,
            &ir.ir_id,
            &ir.ir_digest,
            &procedure.procedure_id,
            &procedure.procedure_digest,
            recognized_anchors,
            verifier_ref,
        ),
        "verification attempt",
    )
}

#[allow(clippy::too_many_arguments)]
fn admission_attempt_digest(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compilation_receipt: &CompilationReceipt,
    ir: &CantorProcessIr,
    procedure: &CompiledProcedureIdentity,
    verification_receipt: &VerificationReceipt,
    policy: &FakeObserverAdmissionPolicy,
) -> Result<ContentDigest, EvaluationFault> {
    digest_serialized(
        &(
            &candidate.candidate_id,
            &candidate.source_digest,
            &validation_receipt.receipt_id,
            &validation_receipt.receipt_digest,
            &compilation_receipt.receipt_id,
            &compilation_receipt.receipt_digest,
            &ir.ir_id,
            &ir.ir_digest,
            &procedure.procedure_id,
            &procedure.procedure_digest,
            &verification_receipt.receipt_id,
            &verification_receipt.receipt_digest,
            &policy.policy_ref,
            &policy.policy_digest,
        ),
        "admission attempt",
    )
}

fn digest_serialized<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<ContentDigest, EvaluationFault> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| machine_fault(format!("{label} serialization failed: {error}")))?;
    Ok(sha256_bytes(&bytes))
}

fn derived_id(prefix: &str, digest: &ContentDigest) -> Result<SemanticId, EvaluationFault> {
    SemanticId::new(format!("{prefix}:{}:{}", digest.algorithm, digest.value))
}

fn empty_sha256() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn machine_fault(error: impl ToString) -> EvaluationFault {
    EvaluationFault::new(crate::FaultKind::MachineForm, error.to_string())
}
