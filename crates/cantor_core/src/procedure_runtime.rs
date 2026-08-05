//! Immutable in-memory catalogue and bounded effectless CPPE-I05 interpreter.
//!
//! The interpreter executes the local deterministic operation subset needed to
//! establish the invocation waist. Multi-process messaging, yielding, logical
//! waits, reactivation, and joins are refused with a typed CPPE-I06 residual.
//! No operation in this module performs I/O or mutates caller-owned state.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    AdmissionDecision, AdmissionDisposition, AwaitedCondition, CantorProcessIr, CatalogueReceipt,
    CatalogueStatus, CompiledProcedureIdentity, ConsumedBudget, ContentDigest, EvaluationFault,
    InvocationDisposition, InvocationRequest, InvocationResult, PhaseDisposition,
    ProcedureCatalogueEntry, ProcedureCatalogueState, ProcedureFault, ProcedureFaultCategory,
    ProcedureMessage, ProcedurePhase, ProcedureSchema, ProcedureType, ProcedureValue,
    ProcessBudgetState, ProcessDefinition, ProcessInstanceState, ProcessLifecycle,
    ProcessOperation, ProcessStep, ReceiptEvidence, RevocationRecord, SchemaKind, SemanticId,
    SemanticTrace, SemanticTraceEvent, TraceEventKind, compute_admission_disposition_digest,
    compute_anchor_set_digest, compute_compiled_procedure_digest, compute_process_ir_digest,
    sha256_bytes,
};

pub const CPPE_CATALOGUE_PRINCIPAL_ID: &str = "cantor-in-memory-catalogue/0.1";
pub const CPPE_INTERPRETER_ID: &str = "cantor-effectless-interpreter/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogueTransition {
    pub receipt: CatalogueReceipt,
    pub successor: Option<ProcedureCatalogueState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationOutcome {
    pub record: RevocationRecord,
    pub successor: ProcedureCatalogueState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpretationOutcome {
    pub result: InvocationResult,
    pub steps: Vec<ProcessStep>,
    pub continuations: BTreeMap<SemanticId, crate::SerializedContinuation>,
    pub messages: BTreeMap<SemanticId, ProcedureMessage>,
}

pub fn empty_procedure_catalogue() -> Result<ProcedureCatalogueState, EvaluationFault> {
    let mut catalogue = ProcedureCatalogueState {
        generation: 0,
        generation_digest: empty_sha256(),
        entries: BTreeMap::new(),
        aliases: BTreeMap::new(),
        revocations: BTreeMap::new(),
    };
    catalogue.generation_digest = compute_procedure_catalogue_digest(&catalogue)?;
    Ok(catalogue)
}

pub fn insert_admitted_procedure(
    catalogue: &ProcedureCatalogueState,
    procedure: &CompiledProcedureIdentity,
    admission: &AdmissionDisposition,
    aliases: BTreeSet<String>,
) -> Result<CatalogueTransition, EvaluationFault> {
    let principal_ref = SemanticId::new(CPPE_CATALOGUE_PRINCIPAL_ID)?;
    let attempt_digest = digest_serialized(
        &(
            &catalogue.generation_digest,
            &procedure.procedure_id,
            &procedure.procedure_digest,
            &admission.disposition_id,
            &admission.disposition_digest,
            &aliases,
            &principal_ref,
        ),
        "catalogue insertion attempt",
    )?;
    let refusal = validate_catalogue_state(catalogue)
        .and_then(|_| validate_insert_inputs(catalogue, procedure, admission, &aliases));
    if let Err(fault) = refusal {
        return refused_catalogue_transition(
            catalogue,
            procedure,
            admission,
            principal_ref,
            attempt_digest,
            fault.message,
        );
    }

    let mut successor = catalogue.clone();
    successor.generation = successor
        .generation
        .checked_add(1)
        .ok_or_else(|| machine_fault("catalogue generation overflow"))?;
    successor.entries.insert(
        procedure.procedure_id.clone(),
        ProcedureCatalogueEntry {
            procedure_ref: procedure.procedure_id.clone(),
            procedure_version: procedure.procedure_version.clone(),
            procedure_digest: procedure.procedure_digest.clone(),
            admission_disposition_ref: admission.disposition_id.clone(),
            admission_disposition_digest: admission.disposition_digest.clone(),
            status: CatalogueStatus::Active,
            aliases: aliases.clone(),
            revocation_ref: None,
        },
    );
    for alias in aliases {
        successor
            .aliases
            .entry(alias)
            .or_default()
            .insert(procedure.procedure_id.clone());
    }
    successor.generation_digest = compute_procedure_catalogue_digest(&successor)?;
    validate_catalogue_state(&successor)?;

    let mut receipt = CatalogueReceipt {
        receipt_id: derived_id("cppe:catalogue-receipt", &attempt_digest)?,
        catalogue_generation_before: catalogue.generation_digest.clone(),
        catalogue_generation_after: Some(successor.generation_digest.clone()),
        procedure_ref: procedure.procedure_id.clone(),
        procedure_digest: procedure.procedure_digest.clone(),
        admission_disposition_ref: admission.disposition_id.clone(),
        admission_disposition_digest: admission.disposition_digest.clone(),
        principal_ref,
        disposition: PhaseDisposition::Passed,
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([admission.disposition_id.clone()]),
            residuals: BTreeSet::from([
                "catalogue predecessor remains immutable".to_owned(),
                "no persistence or invocation performed".to_owned(),
            ]),
            diagnostics: BTreeSet::from([
                "exact admitted procedure inserted into successor value".to_owned()
            ]),
        },
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = compute_catalogue_receipt_digest(&receipt)?;
    Ok(CatalogueTransition {
        receipt,
        successor: Some(successor),
    })
}

pub fn lookup_catalogued_procedure(
    catalogue: &ProcedureCatalogueState,
    procedure_ref: &SemanticId,
) -> Result<Option<ProcedureCatalogueEntry>, EvaluationFault> {
    validate_catalogue_state(catalogue)?;
    Ok(catalogue.entries.get(procedure_ref).cloned())
}

pub fn lookup_catalogue_alias(
    catalogue: &ProcedureCatalogueState,
    alias: &str,
) -> Result<BTreeSet<SemanticId>, EvaluationFault> {
    validate_catalogue_state(catalogue)?;
    if alias.trim().is_empty() {
        return Err(machine_fault("catalogue alias cannot be blank"));
    }
    Ok(catalogue.aliases.get(alias).cloned().unwrap_or_default())
}

pub fn revoke_catalogued_procedure(
    catalogue: &ProcedureCatalogueState,
    procedure_ref: &SemanticId,
    successor_status: CatalogueStatus,
    principal_ref: SemanticId,
    reason: String,
    evidence_refs: BTreeSet<SemanticId>,
    logical_time: u64,
) -> Result<RevocationOutcome, EvaluationFault> {
    validate_catalogue_state(catalogue)?;
    let entry = catalogue
        .entries
        .get(procedure_ref)
        .ok_or_else(|| machine_fault("revocation targets a missing procedure"))?;
    if entry.status != CatalogueStatus::Active
        || !matches!(
            successor_status,
            CatalogueStatus::Suspended | CatalogueStatus::Revoked | CatalogueStatus::Superseded
        )
    {
        return Err(machine_fault(
            "revocation requires an active predecessor and terminal or suspended successor",
        ));
    }
    if reason.trim().is_empty() {
        return Err(machine_fault("revocation reason cannot be blank"));
    }
    let seed = digest_serialized(
        &(
            &catalogue.generation_digest,
            procedure_ref,
            entry.status,
            successor_status,
            &principal_ref,
            &reason,
            &evidence_refs,
            logical_time,
        ),
        "revocation attempt",
    )?;
    let mut record = RevocationRecord {
        revocation_id: derived_id("cppe:revocation", &seed)?,
        procedure_ref: procedure_ref.clone(),
        predecessor_status: entry.status,
        successor_status,
        principal_ref,
        reason,
        evidence_refs,
        logical_time,
        record_digest: empty_sha256(),
    };
    record.record_digest = compute_revocation_record_digest(&record)?;

    let mut successor = catalogue.clone();
    successor.generation = successor
        .generation
        .checked_add(1)
        .ok_or_else(|| machine_fault("catalogue generation overflow"))?;
    let successor_entry = successor
        .entries
        .get_mut(procedure_ref)
        .ok_or_else(|| machine_fault("revocation target disappeared"))?;
    successor_entry.status = successor_status;
    successor_entry.revocation_ref = Some(record.revocation_id.clone());
    successor
        .revocations
        .insert(record.revocation_id.clone(), record.clone());
    successor.generation_digest = compute_procedure_catalogue_digest(&successor)?;
    validate_catalogue_state(&successor)?;
    Ok(RevocationOutcome { record, successor })
}

pub fn validate_catalogue_state(
    catalogue: &ProcedureCatalogueState,
) -> Result<(), EvaluationFault> {
    if compute_procedure_catalogue_digest(catalogue)? != catalogue.generation_digest {
        return Err(machine_fault("catalogue generation digest mismatch"));
    }
    for (procedure_ref, entry) in &catalogue.entries {
        if procedure_ref != &entry.procedure_ref {
            return Err(machine_fault(
                "catalogue entry key differs from procedure identity",
            ));
        }
        if entry.status == CatalogueStatus::Active && entry.revocation_ref.is_some() {
            return Err(machine_fault(
                "active catalogue entry carries revocation evidence",
            ));
        }
        if entry.status != CatalogueStatus::Active {
            let revocation_ref = entry.revocation_ref.as_ref().ok_or_else(|| {
                machine_fault("inactive catalogue entry lacks revocation evidence")
            })?;
            let record = catalogue
                .revocations
                .get(revocation_ref)
                .ok_or_else(|| machine_fault("catalogue entry references missing revocation"))?;
            if record.procedure_ref != *procedure_ref
                || record.successor_status != entry.status
                || compute_revocation_record_digest(record)? != record.record_digest
            {
                return Err(machine_fault("catalogue revocation lineage mismatch"));
            }
        }
        for alias in &entry.aliases {
            if alias.trim().is_empty()
                || !catalogue
                    .aliases
                    .get(alias)
                    .is_some_and(|targets| targets.contains(procedure_ref))
            {
                return Err(machine_fault("catalogue entry alias projection mismatch"));
            }
        }
    }
    for (alias, targets) in &catalogue.aliases {
        if alias.trim().is_empty() || targets.is_empty() {
            return Err(machine_fault(
                "catalogue alias projection is blank or empty",
            ));
        }
        for target in targets {
            if !catalogue
                .entries
                .get(target)
                .is_some_and(|entry| entry.aliases.contains(alias))
            {
                return Err(machine_fault(
                    "catalogue alias has no reciprocal entry binding",
                ));
            }
        }
    }
    Ok(())
}

pub fn compute_procedure_catalogue_digest(
    catalogue: &ProcedureCatalogueState,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = catalogue.clone();
    body.generation_digest = empty_sha256();
    digest_serialized(&body, "procedure catalogue")
}

pub fn compute_catalogue_receipt_digest(
    receipt: &CatalogueReceipt,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = receipt.clone();
    body.receipt_digest = empty_sha256();
    digest_serialized(&body, "catalogue receipt")
}

pub fn compute_revocation_record_digest(
    record: &RevocationRecord,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = record.clone();
    body.record_digest = empty_sha256();
    digest_serialized(&body, "revocation record")
}

pub fn compute_semantic_trace_digest(
    trace: &SemanticTrace,
) -> Result<ContentDigest, EvaluationFault> {
    let mut body = trace.clone();
    body.trace_digest = empty_sha256();
    digest_serialized(&body, "semantic trace")
}

#[allow(clippy::too_many_arguments)]
pub fn invoke_catalogued_procedure(
    catalogue: &ProcedureCatalogueState,
    procedure: &CompiledProcedureIdentity,
    ir: &CantorProcessIr,
    admission: &AdmissionDisposition,
    request: &InvocationRequest,
) -> Result<InterpretationOutcome, EvaluationFault> {
    let validation = validate_invocation_inputs(catalogue, procedure, ir, admission, request);
    if let Err(fault) = validation {
        return invocation_fault_outcome(
            procedure,
            request,
            ProcedureFaultCategory::StaleGeneration,
            InvocationDisposition::Faulted,
            fault.message,
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            ConsumedBudget {
                logical_time: 0,
                steps: 0,
                memory_units: 0,
                messages: 0,
                trace_events: 0,
            },
        );
    }
    if ir.process_definitions.len() != 1 {
        return invocation_fault_outcome(
            procedure,
            request,
            ProcedureFaultCategory::UnsupportedVersion,
            InvocationDisposition::Faulted,
            "CPPE-I05 local interpreter requires exactly one process; multi-process coordination is CPPE-I06"
                .to_owned(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            ConsumedBudget {
                logical_time: 0,
                steps: 0,
                memory_units: 0,
                messages: 0,
                trace_events: 0,
            },
        );
    }
    let definition = ir
        .process_definitions
        .values()
        .next()
        .ok_or_else(|| machine_fault("verified IR has no process"))?;
    interpret_local_process(procedure, ir, admission, request, definition)
}

fn validate_insert_inputs(
    catalogue: &ProcedureCatalogueState,
    procedure: &CompiledProcedureIdentity,
    admission: &AdmissionDisposition,
    aliases: &BTreeSet<String>,
) -> Result<(), EvaluationFault> {
    if catalogue.entries.contains_key(&procedure.procedure_id) {
        return Err(machine_fault(
            "catalogue already contains the exact procedure",
        ));
    }
    if compute_compiled_procedure_digest(procedure)? != procedure.procedure_digest
        || compute_admission_disposition_digest(admission)? != admission.disposition_digest
        || admission.decision == AdmissionDecision::Refuse
        || admission.procedure_ref != procedure.procedure_id
        || admission.procedure_digest != procedure.procedure_digest
        || admission.compiler_ref != procedure.compiler_ref
        || admission.ir_ref != procedure.ir_ref
        || admission.ir_digest != procedure.ir_digest
    {
        return Err(machine_fault(
            "catalogue insertion requires one exact active admission",
        ));
    }
    if aliases.iter().any(|alias| alias.trim().is_empty()) {
        return Err(machine_fault("catalogue alias cannot be blank"));
    }
    Ok(())
}

fn refused_catalogue_transition(
    catalogue: &ProcedureCatalogueState,
    procedure: &CompiledProcedureIdentity,
    admission: &AdmissionDisposition,
    principal_ref: SemanticId,
    attempt_digest: ContentDigest,
    diagnostic: String,
) -> Result<CatalogueTransition, EvaluationFault> {
    let mut receipt = CatalogueReceipt {
        receipt_id: derived_id("cppe:catalogue-receipt", &attempt_digest)?,
        catalogue_generation_before: catalogue.generation_digest.clone(),
        catalogue_generation_after: None,
        procedure_ref: procedure.procedure_id.clone(),
        procedure_digest: procedure.procedure_digest.clone(),
        admission_disposition_ref: admission.disposition_id.clone(),
        admission_disposition_digest: admission.disposition_digest.clone(),
        principal_ref,
        disposition: PhaseDisposition::Refused,
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([admission.disposition_id.clone()]),
            residuals: BTreeSet::from([
                "catalogue predecessor preserved without successor".to_owned(),
                "no persistence or invocation performed".to_owned(),
            ]),
            diagnostics: BTreeSet::from([diagnostic]),
        },
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = compute_catalogue_receipt_digest(&receipt)?;
    Ok(CatalogueTransition {
        receipt,
        successor: None,
    })
}

fn validate_invocation_inputs(
    catalogue: &ProcedureCatalogueState,
    procedure: &CompiledProcedureIdentity,
    ir: &CantorProcessIr,
    admission: &AdmissionDisposition,
    request: &InvocationRequest,
) -> Result<(), EvaluationFault> {
    validate_catalogue_state(catalogue)?;
    let entry = catalogue
        .entries
        .get(&request.admitted_procedure_ref)
        .ok_or_else(|| machine_fault("invocation procedure is absent from catalogue"))?;
    if entry.status != CatalogueStatus::Active
        || entry.procedure_ref != procedure.procedure_id
        || entry.procedure_digest != procedure.procedure_digest
        || entry.admission_disposition_ref != admission.disposition_id
        || entry.admission_disposition_digest != admission.disposition_digest
        || request.procedure_digest != procedure.procedure_digest
        || request.admission_disposition_ref != admission.disposition_id
        || request.admission_disposition_digest != admission.disposition_digest
        || request.catalogue_generation_digest != catalogue.generation_digest
        || request.schema_set_digest != ir.schema_set.schema_set_digest
        || request.sop_anchor_set_digest != compute_anchor_set_digest(&ir.sop_anchors)?
        || request.policy_ref != admission.policy_ref
        || request.policy_digest != admission.policy_digest
        || admission.decision == AdmissionDecision::Refuse
        || admission.procedure_ref != procedure.procedure_id
        || admission.procedure_digest != procedure.procedure_digest
        || admission.ir_ref != ir.ir_id
        || admission.ir_digest != ir.ir_digest
        || compute_admission_disposition_digest(admission)? != admission.disposition_digest
        || compute_compiled_procedure_digest(procedure)? != procedure.procedure_digest
        || compute_process_ir_digest(ir)? != ir.ir_digest
    {
        return Err(machine_fault(
            "invocation has stale or substituted catalogue lineage",
        ));
    }
    if !admission
        .permitted_invocation_contexts
        .contains(&request.purpose)
    {
        return Err(machine_fault(
            "invocation purpose is outside admitted contexts",
        ));
    }
    if request.budgets.step_limit == 0
        || request.budgets.memory_unit_limit == 0
        || request.budgets.message_limit == 0
        || request.budgets.trace_event_limit == 0
        || request.budgets.logical_time_limit == 0
        || request.budgets.step_limit > ir.bounds.maximum_transitions
        || request.budgets.memory_unit_limit > ir.bounds.maximum_memory_units
        || request.budgets.message_limit > ir.bounds.maximum_messages
        || request.budgets.trace_event_limit > ir.bounds.maximum_trace_events
    {
        return Err(machine_fault(
            "invocation budgets are zero or exceed procedure bounds",
        ));
    }
    let input_schema = ir
        .schema_set
        .schemas
        .get(&request.input_schema_ref)
        .ok_or_else(|| machine_fault("invocation input schema is missing"))?;
    let output_schema = ir
        .schema_set
        .schemas
        .get(&request.expected_output_schema_ref)
        .ok_or_else(|| machine_fault("invocation output schema is missing"))?;
    if input_schema.kind != SchemaKind::Input
        || output_schema.kind != SchemaKind::Output
        || !value_matches_schema(&request.input, input_schema, &ir.schema_set.schemas, 64)?
    {
        return Err(machine_fault("invocation input or schema role is invalid"));
    }
    Ok(())
}

fn interpret_local_process(
    procedure: &CompiledProcedureIdentity,
    ir: &CantorProcessIr,
    admission: &AdmissionDisposition,
    request: &InvocationRequest,
    definition: &ProcessDefinition,
) -> Result<InterpretationOutcome, EvaluationFault> {
    let instance_seed = digest_serialized(
        &(&request.invocation_id, &definition.process_definition_id),
        "process instance",
    )?;
    let process_instance_id = derived_id("cppe:process-instance", &instance_seed)?;
    let mut local_state = definition.initial_state.clone();
    set_binding(&mut local_state, "input", request.input.clone())?;
    let state_id = state_identity(
        &request.invocation_id,
        &process_instance_id,
        1,
        &local_state,
    )?;
    let mut state = ProcessInstanceState {
        state_id,
        invocation_ref: request.invocation_id.clone(),
        process_instance_id: process_instance_id.clone(),
        generation: 1,
        definition_ref: definition.process_definition_id.clone(),
        region_ref: definition.entry_region_ref.clone(),
        instruction_index: 0,
        local_state,
        inbox_frontier: BTreeSet::new(),
        outbox_frontier: BTreeSet::new(),
        awaited_condition: AwaitedCondition::None,
        lifecycle: ProcessLifecycle::Ready,
        logical_time: request.initial_logical_time,
        remaining_budgets: ProcessBudgetState {
            transitions_remaining: request.budgets.step_limit,
            messages_remaining: request.budgets.message_limit,
            memory_units_remaining: request.budgets.memory_unit_limit,
            trace_events_remaining: request.budgets.trace_event_limit,
        },
    };
    let mut steps = Vec::new();
    let mut trace_events = Vec::new();
    let mut last_value = None;
    push_trace(
        &mut trace_events,
        request,
        procedure,
        Some(&state),
        TraceEventKind::InvocationStarted,
        &request.input,
    )?;

    loop {
        if state.remaining_budgets.transitions_remaining == 0
            || trace_events.len() as u64 + 2 > request.budgets.trace_event_limit
        {
            let consumed = consumed_from(&trace_events, 0, steps.len() as u64);
            return invocation_fault_outcome(
                procedure,
                request,
                ProcedureFaultCategory::ResourceExhausted,
                InvocationDisposition::BudgetRefused,
                "interpreter step or trace budget exhausted".to_owned(),
                steps,
                BTreeMap::from([(state.state_id.clone(), state)]),
                trace_events,
                consumed,
            );
        }
        let region = definition
            .control_regions
            .get(&state.region_ref)
            .ok_or_else(|| machine_fault("interpreter state references a missing region"))?;
        let instruction = region
            .instructions
            .get(state.instruction_index as usize)
            .ok_or_else(|| machine_fault("interpreter instruction index is out of range"))?;
        let before = state.clone();
        state.lifecycle = ProcessLifecycle::Operating;
        let logical_before = state.logical_time;
        state.logical_time = state
            .logical_time
            .checked_add(1)
            .ok_or_else(|| machine_fault("logical time overflow"))?;
        if state.logical_time - request.initial_logical_time > request.budgets.logical_time_limit {
            let consumed = consumed_from(&trace_events, 0, steps.len() as u64);
            return invocation_fault_outcome(
                procedure,
                request,
                ProcedureFaultCategory::ResourceExhausted,
                InvocationDisposition::BudgetRefused,
                "interpreter logical-time budget exhausted".to_owned(),
                steps,
                BTreeMap::from([(before.state_id.clone(), before)]),
                trace_events,
                consumed,
            );
        }
        state.remaining_budgets.transitions_remaining -= 1;
        let mut selected_successor = None;
        let mut returned = None;
        let mut fault_category = None;
        let mut fault_message = None;
        let operation_result = (|| -> Result<(), EvaluationFault> {
            match instruction.operation {
                ProcessOperation::Bind | ProcessOperation::Inspect => {
                    let value = instruction
                        .operands
                        .first()
                        .map(|operand| {
                            resolve_value(&operand.value, &request.input, &state.local_state)
                        })
                        .transpose()?
                        .ok_or_else(|| machine_fault("bind or inspect requires one operand"))?;
                    let binding = instruction.result_binding.as_deref().ok_or_else(|| {
                        machine_fault("bind or inspect requires a result binding")
                    })?;
                    set_binding(&mut state.local_state, binding, value.clone())?;
                    last_value = Some(value);
                }
                ProcessOperation::Compare => {
                    if instruction.operands.len() != 2 {
                        return Err(machine_fault("compare requires exactly two operands"));
                    }
                    let left = resolve_value(
                        &instruction.operands[0].value,
                        &request.input,
                        &state.local_state,
                    )?;
                    let right = resolve_value(
                        &instruction.operands[1].value,
                        &request.input,
                        &state.local_state,
                    )?;
                    let value = ProcedureValue::Boolean {
                        value: left == right,
                    };
                    let binding = instruction
                        .result_binding
                        .as_deref()
                        .ok_or_else(|| machine_fault("compare requires a result binding"))?;
                    set_binding(&mut state.local_state, binding, value.clone())?;
                    last_value = Some(value);
                }
                ProcessOperation::Branch => {
                    let condition = instruction
                        .operands
                        .first()
                        .map(|operand| {
                            resolve_value(&operand.value, &request.input, &state.local_state)
                        })
                        .transpose()?
                        .ok_or_else(|| machine_fault("branch requires a condition"))?;
                    let ProcedureValue::Boolean { value } = condition else {
                        return Err(machine_fault("branch condition is not boolean"));
                    };
                    if instruction.successor_region_refs.len() != 2 {
                        return Err(machine_fault("branch requires true and false successors"));
                    }
                    selected_successor =
                        Some(instruction.successor_region_refs[usize::from(!value)].clone());
                }
                ProcessOperation::Select => {
                    let index = instruction
                        .operands
                        .first()
                        .map(|operand| {
                            resolve_value(&operand.value, &request.input, &state.local_state)
                        })
                        .transpose()?
                        .ok_or_else(|| machine_fault("select requires an index"))?;
                    let ProcedureValue::Integer { value } = index else {
                        return Err(machine_fault("select index is not an integer"));
                    };
                    let index = usize::try_from(value).map_err(|_| {
                        machine_fault("select index is negative or over host bound")
                    })?;
                    selected_successor = instruction.successor_region_refs.get(index).cloned();
                    if selected_successor.is_none() {
                        return Err(machine_fault("select index exceeds successor set"));
                    }
                }
                ProcessOperation::MapBounded => {
                    let value = instruction
                        .operands
                        .first()
                        .map(|operand| {
                            resolve_value(&operand.value, &request.input, &state.local_state)
                        })
                        .transpose()?
                        .ok_or_else(|| machine_fault("bounded map requires a list"))?;
                    let ProcedureValue::List { members } = &value else {
                        return Err(machine_fault("bounded map operand is not a list"));
                    };
                    if members.len() as u64 > ir.bounds.maximum_collection_items {
                        return Err(machine_fault("bounded map exceeds collection bound"));
                    }
                    let binding = instruction
                        .result_binding
                        .as_deref()
                        .ok_or_else(|| machine_fault("bounded map requires a result binding"))?;
                    set_binding(&mut state.local_state, binding, value.clone())?;
                    last_value = Some(value);
                }
                ProcessOperation::Return => {
                    returned = Some(
                        instruction
                            .operands
                            .first()
                            .map(|operand| {
                                resolve_value(&operand.value, &request.input, &state.local_state)
                            })
                            .transpose()?
                            .or(last_value.clone())
                            .unwrap_or_else(|| request.input.clone()),
                    );
                    state.lifecycle = ProcessLifecycle::TerminalReturn;
                }
                ProcessOperation::Fault => {
                    fault_category = Some(ProcedureFaultCategory::InternalInvariant);
                    fault_message =
                        Some("procedure executed its declared fault instruction".to_owned());
                    state.lifecycle = ProcessLifecycle::TerminalFault;
                }
                ProcessOperation::Emit
                | ProcessOperation::Receive
                | ProcessOperation::Yield
                | ProcessOperation::WaitLogical
                | ProcessOperation::Reactivate
                | ProcessOperation::Join => {
                    fault_category = Some(ProcedureFaultCategory::UnsupportedVersion);
                    fault_message = Some(
                    "coordination operation is reserved for the separately proved CPPE-I06 runtime"
                        .to_owned(),
                );
                    state.lifecycle = ProcessLifecycle::TerminalFault;
                }
            }
            Ok(())
        })();
        if let Err(fault) = operation_result {
            returned = None;
            fault_category = Some(ProcedureFaultCategory::TypeMismatch);
            fault_message = Some(fault.message);
            state.lifecycle = ProcessLifecycle::TerminalFault;
        }
        let memory_units = serde_json::to_vec(&state.local_state)
            .map_err(|error| machine_fault(format!("local state serialization failed: {error}")))?
            .len() as u64;
        if memory_units > request.budgets.memory_unit_limit {
            let consumed = consumed_from(&trace_events, memory_units, steps.len() as u64);
            return invocation_fault_outcome(
                procedure,
                request,
                ProcedureFaultCategory::ResourceExhausted,
                InvocationDisposition::BudgetRefused,
                "interpreter memory budget exhausted".to_owned(),
                steps,
                BTreeMap::from([(before.state_id.clone(), before)]),
                trace_events,
                consumed,
            );
        }
        if returned.is_none() && fault_category.is_none() {
            if let Some(successor) = selected_successor.or_else(|| {
                if instruction.successor_region_refs.len() == 1 {
                    instruction.successor_region_refs.first().cloned()
                } else {
                    None
                }
            }) {
                state.region_ref = successor;
                state.instruction_index = 0;
            } else if (state.instruction_index as usize) + 1 < region.instructions.len() {
                state.instruction_index += 1;
            } else {
                return Err(machine_fault(
                    "nonterminal instruction has no deterministic successor",
                ));
            }
            state.lifecycle = ProcessLifecycle::Ready;
        }
        state.generation += 1;
        state.state_id = state_identity(
            &request.invocation_id,
            &process_instance_id,
            state.generation,
            &state.local_state,
        )?;
        let step_seed = digest_serialized(
            &(
                &request.invocation_id,
                &instruction.instruction_id,
                state.generation,
            ),
            "process step",
        )?;
        let step = ProcessStep {
            step_id: derived_id("cppe:process-step", &step_seed)?,
            invocation_ref: request.invocation_id.clone(),
            process_instance_ref: process_instance_id.clone(),
            input_generation: before.generation,
            instruction_ref: instruction.instruction_id.clone(),
            input_message_refs: BTreeSet::new(),
            emitted_message_refs: BTreeSet::new(),
            successor_state: if returned.is_none() && fault_category.is_none() {
                Some(state.clone())
            } else {
                None
            },
            returned_value: returned.clone(),
            fault_ref: fault_category.as_ref().map(|_| {
                derived_id("cppe:procedure-fault", &step_seed)
                    .expect("digest-derived fault identity")
            }),
            logical_time_before: logical_before,
            logical_time_after: state.logical_time,
            consumed_budget: ConsumedBudget {
                logical_time: 1,
                steps: 1,
                memory_units,
                messages: 0,
                trace_events: 1,
            },
        };
        steps.push(step);
        push_trace(
            &mut trace_events,
            request,
            procedure,
            Some(&state),
            if returned.is_some() {
                TraceEventKind::Returned
            } else if fault_category.is_some() {
                TraceEventKind::Faulted
            } else {
                TraceEventKind::StateReplaced
            },
            returned.as_ref().unwrap_or(&state.local_state),
        )?;
        if let Some(output) = returned {
            let output_schema = ir
                .schema_set
                .schemas
                .get(&request.expected_output_schema_ref)
                .ok_or_else(|| machine_fault("output schema disappeared"))?;
            if !value_matches_schema(&output, output_schema, &ir.schema_set.schemas, 64)? {
                let consumed = consumed_from(&trace_events, memory_units, steps.len() as u64);
                return invocation_fault_outcome(
                    procedure,
                    request,
                    ProcedureFaultCategory::SchemaMismatch,
                    InvocationDisposition::Faulted,
                    "returned value does not satisfy expected output schema".to_owned(),
                    steps,
                    BTreeMap::from([(state.state_id.clone(), state)]),
                    trace_events,
                    consumed,
                );
            }
            push_trace(
                &mut trace_events,
                request,
                procedure,
                Some(&state),
                TraceEventKind::InvocationCompleted,
                &output,
            )?;
            let consumed = consumed_from(&trace_events, memory_units, steps.len() as u64);
            let trace = build_trace(request, procedure, trace_events)?;
            return Ok(InterpretationOutcome {
                result: InvocationResult {
                    invocation_ref: request.invocation_id.clone(),
                    procedure_ref: procedure.procedure_id.clone(),
                    disposition: InvocationDisposition::Returned,
                    output: Some(output),
                    output_sensitivity: request.input_sensitivity,
                    fault: None,
                    final_process_states: BTreeMap::from([(state.state_id.clone(), state)]),
                    semantic_trace: trace,
                    consumed_budget: consumed,
                    residuals: BTreeSet::from([
                        "catalogue and invocation inputs remain immutable".to_owned(),
                        "coordination operations remain CPPE-I06".to_owned(),
                    ]),
                    proof_refs: BTreeSet::from([
                        admission.disposition_id.clone(),
                        request.admission_disposition_ref.clone(),
                    ]),
                    retention_policy_ref: request.retention_policy_ref.clone(),
                },
                steps,
                continuations: BTreeMap::new(),
                messages: BTreeMap::new(),
            });
        }
        if let Some(category) = fault_category {
            let consumed = consumed_from(&trace_events, memory_units, steps.len() as u64);
            return invocation_fault_outcome(
                procedure,
                request,
                category,
                InvocationDisposition::Faulted,
                fault_message.unwrap_or_else(|| "procedure fault".to_owned()),
                steps,
                BTreeMap::from([(state.state_id.clone(), state)]),
                trace_events,
                consumed,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn invocation_fault_outcome(
    procedure: &CompiledProcedureIdentity,
    request: &InvocationRequest,
    category: ProcedureFaultCategory,
    disposition: InvocationDisposition,
    message: String,
    steps: Vec<ProcessStep>,
    final_process_states: BTreeMap<SemanticId, ProcessInstanceState>,
    trace_events: Vec<SemanticTraceEvent>,
    consumed_budget: ConsumedBudget,
) -> Result<InterpretationOutcome, EvaluationFault> {
    let fault_seed = digest_serialized(
        &(
            &request.invocation_id,
            &procedure.procedure_id,
            category,
            &message,
            &consumed_budget,
        ),
        "invocation fault",
    )?;
    let fault_id = steps
        .last()
        .and_then(|step| step.fault_ref.clone())
        .unwrap_or(derived_id("cppe:procedure-fault", &fault_seed)?);
    let fault = ProcedureFault {
        fault_id,
        phase: ProcedurePhase::Invocation,
        category,
        subject_refs: BTreeSet::from([
            request.invocation_id.clone(),
            procedure.procedure_id.clone(),
        ]),
        expected_versions: BTreeMap::from([(
            "interpreter".to_owned(),
            CPPE_INTERPRETER_ID.to_owned(),
        )]),
        observed_versions: BTreeMap::new(),
        evidence_refs: BTreeSet::from([request.admission_disposition_ref.clone()]),
        consumed_budget: consumed_budget.clone(),
        trace_location: trace_events.last().map(|event| event.logical_index),
        safe_residuals: BTreeSet::from([
            message,
            "catalogue, procedure, IR, admission, and request inputs remain unchanged".to_owned(),
        ]),
    };
    let trace = build_trace(request, procedure, trace_events)?;
    Ok(InterpretationOutcome {
        result: InvocationResult {
            invocation_ref: request.invocation_id.clone(),
            procedure_ref: procedure.procedure_id.clone(),
            disposition,
            output: None,
            output_sensitivity: request.input_sensitivity,
            fault: Some(fault),
            final_process_states,
            semantic_trace: trace,
            consumed_budget,
            residuals: BTreeSet::from([
                "no external effect or successor catalogue state".to_owned()
            ]),
            proof_refs: BTreeSet::from([request.admission_disposition_ref.clone()]),
            retention_policy_ref: request.retention_policy_ref.clone(),
        },
        steps,
        continuations: BTreeMap::new(),
        messages: BTreeMap::new(),
    })
}

fn resolve_value(
    value: &ProcedureValue,
    input: &ProcedureValue,
    local: &ProcedureValue,
) -> Result<ProcedureValue, EvaluationFault> {
    let ProcedureValue::IdentityReference { value: reference } = value else {
        return Ok(value.clone());
    };
    if reference.as_str() == "input:root" {
        return Ok(input.clone());
    }
    if let Some(field) = reference.as_str().strip_prefix("input:") {
        return record_field(input, field);
    }
    if let Some(field) = reference.as_str().strip_prefix("local:") {
        return record_field(local, field);
    }
    Ok(value.clone())
}

fn record_field(value: &ProcedureValue, field: &str) -> Result<ProcedureValue, EvaluationFault> {
    let ProcedureValue::Record { fields } = value else {
        return Err(machine_fault("binding lookup requires a record value"));
    };
    fields
        .get(field)
        .cloned()
        .ok_or_else(|| machine_fault(format!("binding field {field:?} is missing")))
}

fn set_binding(
    local: &mut ProcedureValue,
    binding: &str,
    value: ProcedureValue,
) -> Result<(), EvaluationFault> {
    if binding.trim().is_empty() {
        return Err(machine_fault("result binding cannot be blank"));
    }
    let ProcedureValue::Record { fields } = local else {
        return Err(machine_fault("local process state must be a record"));
    };
    fields.insert(binding.to_owned(), value);
    Ok(())
}

fn value_matches_schema(
    value: &ProcedureValue,
    schema: &ProcedureSchema,
    schemas: &BTreeMap<SemanticId, ProcedureSchema>,
    depth: u64,
) -> Result<bool, EvaluationFault> {
    if depth == 0 {
        return Ok(false);
    }
    if !schema.tagged_variants.is_empty() {
        let ProcedureValue::TaggedUnion { tag, value } = value else {
            return Ok(false);
        };
        return schema
            .tagged_variants
            .get(tag)
            .map(|variant| value_matches_type(value, &variant.value_type, schemas, depth - 1))
            .transpose()
            .map(|value| value.unwrap_or(false));
    }
    let ProcedureValue::Record { fields } = value else {
        return Ok(false);
    };
    if fields
        .keys()
        .any(|field| !schema.fields.contains_key(field))
    {
        return Ok(false);
    }
    for field in schema.fields.values() {
        let Some(value) = fields.get(&field.field_name) else {
            if field.required {
                return Ok(false);
            }
            continue;
        };
        if !value_matches_type(value, &field.value_type, schemas, depth - 1)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn value_matches_type(
    value: &ProcedureValue,
    value_type: &ProcedureType,
    schemas: &BTreeMap<SemanticId, ProcedureSchema>,
    depth: u64,
) -> Result<bool, EvaluationFault> {
    if depth == 0 {
        return Ok(false);
    }
    Ok(match (value, value_type) {
        (ProcedureValue::Null, ProcedureType::Null)
        | (ProcedureValue::Boolean { .. }, ProcedureType::Boolean)
        | (ProcedureValue::BytesDigest { .. }, ProcedureType::BytesDigest)
        | (ProcedureValue::IdentityReference { .. }, ProcedureType::IdentityReference { .. }) => {
            true
        }
        (ProcedureValue::Integer { value }, ProcedureType::BoundedInteger { minimum, maximum }) => {
            value >= minimum && value <= maximum
        }
        (
            ProcedureValue::Decimal { canonical },
            ProcedureType::BoundedDecimal {
                minimum, maximum, ..
            },
        ) => canonical >= minimum && canonical <= maximum,
        (ProcedureValue::Text { value }, ProcedureType::BoundedText { maximum_bytes }) => {
            value.len() as u64 <= *maximum_bytes
        }
        (
            ProcedureValue::List { members },
            ProcedureType::List {
                member,
                maximum_items,
            },
        ) => {
            if members.len() as u64 > *maximum_items {
                false
            } else {
                for value in members {
                    if !value_matches_type(value, member, schemas, depth - 1)? {
                        return Ok(false);
                    }
                }
                true
            }
        }
        (
            ProcedureValue::OrderedMap { entries },
            ProcedureType::OrderedMap {
                value,
                maximum_entries,
            },
        ) => {
            if entries.len() as u64 > *maximum_entries {
                false
            } else {
                for member in entries.values() {
                    if !value_matches_type(member, value, schemas, depth - 1)? {
                        return Ok(false);
                    }
                }
                true
            }
        }
        (ProcedureValue::Record { .. }, ProcedureType::Record { schema_ref })
        | (ProcedureValue::TaggedUnion { .. }, ProcedureType::TaggedUnion { schema_ref })
        | (ProcedureValue::TypedFault { .. }, ProcedureType::TypedFault { schema_ref }) => {
            schemas.get(schema_ref).is_some_and(|schema| {
                value_matches_schema(value, schema, schemas, depth - 1).unwrap_or(false)
            })
        }
        _ => false,
    })
}

fn push_trace(
    events: &mut Vec<SemanticTraceEvent>,
    request: &InvocationRequest,
    procedure: &CompiledProcedureIdentity,
    state: Option<&ProcessInstanceState>,
    kind: TraceEventKind,
    payload: &ProcedureValue,
) -> Result<(), EvaluationFault> {
    let index = events.len() as u64;
    let payload_digest = digest_serialized(payload, "trace payload")?;
    let seed = digest_serialized(
        &(&request.invocation_id, index, kind, &payload_digest),
        "trace event",
    )?;
    let predecessors = events
        .last()
        .map(|event| BTreeSet::from([event.event_id.clone()]))
        .unwrap_or_default();
    events.push(SemanticTraceEvent {
        event_id: derived_id("cppe:trace-event", &seed)?,
        logical_index: index,
        kind,
        procedure_ref: procedure.procedure_id.clone(),
        process_ref: state.map(|state| state.process_instance_id.clone()),
        subject_generation: state.map_or(0, |state| state.generation),
        normalized_payload_digest: payload_digest,
        causal_predecessor_refs: predecessors,
    });
    Ok(())
}

fn build_trace(
    request: &InvocationRequest,
    procedure: &CompiledProcedureIdentity,
    events: Vec<SemanticTraceEvent>,
) -> Result<SemanticTrace, EvaluationFault> {
    let seed = digest_serialized(
        &(&request.invocation_id, &procedure.procedure_id, &events),
        "semantic trace identity",
    )?;
    let mut trace = SemanticTrace {
        trace_id: derived_id("cppe:semantic-trace", &seed)?,
        events,
        trace_digest: empty_sha256(),
        sensitivity: request.input_sensitivity,
        retention_policy_ref: request.retention_policy_ref.clone(),
    };
    trace.trace_digest = compute_semantic_trace_digest(&trace)?;
    Ok(trace)
}

fn consumed_from(events: &[SemanticTraceEvent], memory_units: u64, steps: u64) -> ConsumedBudget {
    ConsumedBudget {
        logical_time: steps,
        steps,
        memory_units,
        messages: 0,
        trace_events: events.len() as u64,
    }
}

fn state_identity(
    invocation_ref: &SemanticId,
    process_instance_ref: &SemanticId,
    generation: u64,
    local_state: &ProcedureValue,
) -> Result<SemanticId, EvaluationFault> {
    let digest = digest_serialized(
        &(
            invocation_ref,
            process_instance_ref,
            generation,
            local_state,
        ),
        "process state identity",
    )?;
    derived_id("cppe:process-state", &digest)
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
