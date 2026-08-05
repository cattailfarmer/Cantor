//! Deterministic validation and normalized serialization for CPPE-I02.
//!
//! These functions inspect already-formed records. They do not parse a textual
//! language, lower source, compile, verify, admit, schedule, or execute.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use crate::{
    AdmissionDecision, CPPE_FORM_VERSION, CPPE_IR_VERSION, CantorProcessIr, CatalogueStatus,
    ContentDigest, ControlRegion, EvaluationFault, FaultKind, PhaseDisposition, ProcedureBounds,
    ProcedureCandidate, ProcedureEffectClass, ProcedureFormSet, ProcedureLifecycle,
    ProcedureSchema, ProcedureSchemaSet, ProcedureType, ProcedureValue, ProcessDefinition,
    ProcessInstruction, ProcessLifecycle, SchemaKind, SemanticId,
    compute_admission_disposition_digest, compute_anchor_set_digest,
    compute_catalogue_receipt_digest, compute_effect_declaration_digest,
    compute_procedure_bounds_digest, compute_procedure_catalogue_digest,
    compute_revocation_record_digest, compute_semantic_trace_digest,
    compute_verification_receipt_digest, from_machine_form, sha256_bytes, to_machine_form,
    validate_catalogue_state,
};

const MAX_FORM_RECORDS: usize = 16_384;
const MAX_PROFILE_TEXT_BYTES: usize = 16_384;
const MAX_VALUE_DEPTH: u64 = 64;

pub fn validate_procedure_forms(forms: &ProcedureFormSet) -> Result<(), EvaluationFault> {
    if forms.form_version != CPPE_FORM_VERSION {
        return Err(form_fault(format!(
            "unsupported CPPE form version: {:?}",
            forms.form_version
        )));
    }
    if form_record_count(forms) > MAX_FORM_RECORDS {
        return Err(form_fault(format!(
            "CPPE form set exceeds {MAX_FORM_RECORDS} records"
        )));
    }

    validate_map(
        "candidate",
        &forms.candidates,
        |v| &v.candidate_id,
        validate_candidate,
    )?;
    validate_map(
        "compiled procedure",
        &forms.compiled_procedures,
        |v| &v.procedure_id,
        validate_compiled_identity,
    )?;
    validate_map(
        "schema set",
        &forms.schema_sets,
        |v| &v.schema_set_id,
        validate_schema_set_unbounded,
    )?;
    validate_map(
        "process definition",
        &forms.process_definitions,
        |v| &v.process_definition_id,
        validate_process_definition_unbounded,
    )?;
    validate_map(
        "process IR",
        &forms.process_irs,
        |v| &v.ir_id,
        validate_process_ir,
    )?;
    validate_map(
        "process instance",
        &forms.process_instances,
        |v| &v.state_id,
        |v| {
            validate_text(
                "process lifecycle state",
                format!("{:?}", v.lifecycle).as_str(),
                128,
            )?;
            if v.generation == 0 {
                return Err(form_fault("process instance generation must be positive"));
            }
            validate_value(&v.local_state, u64::MAX, MAX_VALUE_DEPTH)?;
            Ok(())
        },
    )?;
    validate_map(
        "continuation",
        &forms.continuations,
        |v| &v.continuation_id,
        |v| {
            validate_digest("continuation digest", &v.continuation_digest)?;
            if v.process_state.lifecycle == ProcessLifecycle::Operating {
                return Err(form_fault(
                    "serialized continuation cannot contain an operating process",
                ));
            }
            Ok(())
        },
    )?;
    validate_map(
        "process step",
        &forms.process_steps,
        |v| &v.step_id,
        |v| {
            if v.logical_time_after < v.logical_time_before {
                return Err(form_fault("process step logical time moves backward"));
            }
            let terminal_outputs = usize::from(v.successor_state.is_some())
                + usize::from(v.returned_value.is_some())
                + usize::from(v.fault_ref.is_some());
            if terminal_outputs != 1 {
                return Err(form_fault(
                    "process step must produce exactly one successor, return, or fault",
                ));
            }
            Ok(())
        },
    )?;
    validate_map(
        "participant",
        &forms.participants,
        |v| &v.participant_id,
        |v| {
            if v.permitted_message_kinds.is_empty() {
                return Err(form_fault("participant message-kind set cannot be empty"));
            }
            Ok(())
        },
    )?;
    validate_map(
        "message",
        &forms.messages,
        |v| &v.message_id,
        |v| {
            if v.expires_at_logical_time < v.logical_time {
                return Err(form_fault(
                    "message expires before its logical creation time",
                ));
            }
            validate_value(&v.payload, u64::MAX, MAX_VALUE_DEPTH)
        },
    )?;
    validate_map(
        "negotiated frame",
        &forms.negotiated_frames,
        |v| &v.frame_id,
        |v| {
            if v.participant_refs.is_empty() {
                return Err(form_fault(
                    "negotiated frame participant set cannot be empty",
                ));
            }
            for value in v.propositions.values() {
                validate_value(value, u64::MAX, MAX_VALUE_DEPTH)?;
            }
            Ok(())
        },
    )?;
    validate_map(
        "negotiation session",
        &forms.negotiation_sessions,
        |v| &v.session_generation_id,
        |v| {
            validate_text(
                "negotiation purpose",
                &v.purpose,
                MAX_PROFILE_TEXT_BYTES as u64,
            )?;
            if v.required_participant_refs.is_empty() {
                return Err(form_fault("negotiation requires at least one participant"));
            }
            if v.frame_generation != v.frame.generation {
                return Err(form_fault("session and frame generation differ"));
            }
            if v.frame.participant_refs != v.required_participant_refs {
                return Err(form_fault(
                    "negotiated frame participant set differs from required participant set",
                ));
            }
            if !v.participants.contains_key(&v.token_holder_ref) {
                return Err(form_fault(
                    "token holder is absent from session participants",
                ));
            }
            for participant_ref in &v.required_participant_refs {
                if !v.participants.contains_key(participant_ref) {
                    return Err(form_fault(format!(
                        "required participant {participant_ref} is absent"
                    )));
                }
            }
            Ok(())
        },
    )?;
    validate_map(
        "token-ring pass",
        &forms.token_ring_passes,
        |v| &v.pass_id,
        |v| {
            validate_digest("participant-set digest", &v.participant_set_digest)?;
            validate_digest("SOP-anchor-set digest", &v.sop_anchor_set_digest)
        },
    )?;
    validate_receipt_maps(forms)?;
    validate_map(
        "revocation",
        &forms.revocations,
        |v| &v.revocation_id,
        |v| {
            if v.predecessor_status == v.successor_status {
                return Err(form_fault("revocation status transition cannot be a no-op"));
            }
            if !matches!(
                v.successor_status,
                CatalogueStatus::Suspended | CatalogueStatus::Revoked | CatalogueStatus::Superseded
            ) {
                return Err(form_fault(
                    "revocation successor status is not terminal or suspended",
                ));
            }
            validate_text(
                "revocation reason",
                &v.reason,
                MAX_PROFILE_TEXT_BYTES as u64,
            )?;
            validate_digest("revocation record digest", &v.record_digest)?;
            if compute_revocation_record_digest(v)? != v.record_digest {
                return Err(form_fault("revocation record digest mismatch"));
            }
            Ok(())
        },
    )?;
    validate_map(
        "phase receipt set",
        &forms.phase_receipt_sets,
        |v| &v.receipt_set_id,
        |_| Ok(()),
    )?;
    for (key, catalogue) in &forms.catalogues_by_generation_digest {
        let expected = digest_key(&catalogue.generation_digest);
        if key != &expected {
            return Err(form_fault(format!(
                "catalogue key mismatch: expected {expected:?}, observed {key:?}"
            )));
        }
        validate_digest("catalogue generation digest", &catalogue.generation_digest)?;
        if compute_procedure_catalogue_digest(catalogue)? != catalogue.generation_digest {
            return Err(form_fault("catalogue generation digest mismatch"));
        }
        validate_catalogue_state(catalogue)?;
        for (procedure_ref, entry) in &catalogue.entries {
            if procedure_ref != &entry.procedure_ref {
                return Err(form_fault(
                    "catalogue entry key differs from procedure identity",
                ));
            }
            validate_text("procedure version", &entry.procedure_version, 256)?;
            validate_digest("catalogue procedure digest", &entry.procedure_digest)?;
            validate_digest(
                "catalogue admission disposition digest",
                &entry.admission_disposition_digest,
            )?;
            if entry.status == CatalogueStatus::Active && entry.revocation_ref.is_some() {
                return Err(form_fault("active catalogue entry cannot carry revocation"));
            }
        }
        for (alias, targets) in &catalogue.aliases {
            validate_text("catalogue alias", alias, 256)?;
            if targets.is_empty() {
                return Err(form_fault("catalogue alias target set cannot be empty"));
            }
            for target in targets {
                if !catalogue.entries.contains_key(target) {
                    return Err(form_fault(format!(
                        "catalogue alias {alias:?} targets missing procedure {target}"
                    )));
                }
            }
        }
    }
    validate_map(
        "invocation request",
        &forms.invocation_requests,
        |v| &v.invocation_id,
        |v| {
            validate_text(
                "invocation purpose",
                &v.purpose,
                MAX_PROFILE_TEXT_BYTES as u64,
            )?;
            validate_digest(
                "catalogue generation digest",
                &v.catalogue_generation_digest,
            )?;
            validate_digest("invocation procedure digest", &v.procedure_digest)?;
            validate_digest(
                "invocation admission disposition digest",
                &v.admission_disposition_digest,
            )?;
            validate_digest("invocation schema-set digest", &v.schema_set_digest)?;
            validate_digest("invocation SOP anchor-set digest", &v.sop_anchor_set_digest)?;
            validate_digest("invocation policy digest", &v.policy_digest)?;
            validate_value(&v.input, v.budgets.memory_unit_limit, MAX_VALUE_DEPTH)?;
            if v.budgets.step_limit == 0
                || v.budgets.memory_unit_limit == 0
                || v.budgets.message_limit == 0
                || v.budgets.trace_event_limit == 0
            {
                return Err(form_fault("invocation budgets must be positive"));
            }
            Ok(())
        },
    )?;
    validate_map(
        "semantic trace",
        &forms.semantic_traces,
        |v| &v.trace_id,
        |v| {
            validate_digest("trace digest", &v.trace_digest)?;
            if compute_semantic_trace_digest(v)? != v.trace_digest {
                return Err(form_fault("semantic trace digest mismatch"));
            }
            let mut expected_index = 0_u64;
            let mut ids = BTreeSet::new();
            for event in &v.events {
                if event.logical_index != expected_index {
                    return Err(form_fault("semantic trace indexes are not contiguous"));
                }
                if !ids.insert(event.event_id.clone()) {
                    return Err(form_fault(
                        "semantic trace contains a duplicate event identity",
                    ));
                }
                if expected_index == 0 && !event.causal_predecessor_refs.is_empty() {
                    return Err(form_fault(
                        "first semantic trace event cannot have a predecessor",
                    ));
                }
                if expected_index > 0 {
                    let predecessor = &v.events[expected_index as usize - 1].event_id;
                    if event.causal_predecessor_refs != BTreeSet::from([predecessor.clone()]) {
                        return Err(form_fault(
                            "semantic trace event does not bind its exact predecessor",
                        ));
                    }
                }
                validate_digest("trace payload digest", &event.normalized_payload_digest)?;
                expected_index = expected_index.saturating_add(1);
            }
            Ok(())
        },
    )?;
    validate_map(
        "procedure fault",
        &forms.faults,
        |v| &v.fault_id,
        |v| {
            if v.safe_residuals.is_empty() {
                return Err(form_fault("procedure fault must name a safe residual"));
            }
            Ok(())
        },
    )?;
    validate_map(
        "invocation result",
        &forms.invocation_results,
        |v| &v.invocation_ref,
        |v| {
            let payloads = usize::from(v.output.is_some()) + usize::from(v.fault.is_some());
            if payloads != 1 {
                return Err(form_fault(
                    "invocation result must contain exactly one output or fault",
                ));
            }
            if let Some(output) = &v.output {
                validate_value(output, u64::MAX, MAX_VALUE_DEPTH)?;
            }
            if compute_semantic_trace_digest(&v.semantic_trace)? != v.semantic_trace.trace_digest {
                return Err(form_fault("invocation result trace digest mismatch"));
            }
            if v.consumed_budget.trace_events != v.semantic_trace.events.len() as u64 {
                return Err(form_fault(
                    "invocation result trace accounting differs from trace length",
                ));
            }
            for (index, event) in v.semantic_trace.events.iter().enumerate() {
                if event.logical_index != index as u64 || event.procedure_ref != v.procedure_ref {
                    return Err(form_fault(
                        "invocation result trace index or procedure binding mismatch",
                    ));
                }
            }
            for state in v.final_process_states.values() {
                if state.invocation_ref != v.invocation_ref {
                    return Err(form_fault(
                        "invocation result contains a state from another invocation",
                    ));
                }
            }
            Ok(())
        },
    )?;

    validate_relations(forms)
}

pub fn to_normalized_procedure_form(forms: &ProcedureFormSet) -> Result<String, EvaluationFault> {
    validate_procedure_forms(forms)?;
    to_machine_form(forms)
}

pub fn from_normalized_procedure_form(value: &str) -> Result<ProcedureFormSet, EvaluationFault> {
    let forms: ProcedureFormSet = from_machine_form(value)?;
    validate_procedure_forms(&forms)?;
    if to_machine_form(&forms)? != value {
        return Err(form_fault(
            "CPPE machine form is valid JSON but not normalized",
        ));
    }
    Ok(forms)
}

pub fn compute_process_ir_digest(ir: &CantorProcessIr) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = ir.clone();
    digest_body.ir_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    };
    let bytes = serde_json::to_vec(&digest_body)
        .map_err(|error| form_fault(format!("Process IR digest serialization failed: {error}")))?;
    Ok(sha256_bytes(&bytes))
}

pub fn compute_schema_set_digest(
    schema_set: &ProcedureSchemaSet,
) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = schema_set.clone();
    digest_body.schema_set_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    };
    let bytes = serde_json::to_vec(&digest_body)
        .map_err(|error| form_fault(format!("schema-set serialization failed: {error}")))?;
    Ok(sha256_bytes(&bytes))
}

pub fn compute_candidate_source_digest(
    candidate: &ProcedureCandidate,
) -> Result<ContentDigest, EvaluationFault> {
    match (&candidate.source_text, &candidate.normalized_source_form) {
        (Some(source), None) => Ok(sha256_bytes(source.as_bytes())),
        (None, Some(source)) => {
            let bytes = serde_json::to_vec(source).map_err(|error| {
                form_fault(format!(
                    "candidate source-form serialization failed: {error}"
                ))
            })?;
            Ok(sha256_bytes(&bytes))
        }
        _ => Err(form_fault(
            "candidate must contain exactly one source representation before digesting",
        )),
    }
}

pub fn compute_compiled_procedure_digest(
    identity: &crate::CompiledProcedureIdentity,
) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = identity.clone();
    digest_body.procedure_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    };
    let bytes = serde_json::to_vec(&digest_body)
        .map_err(|error| form_fault(format!("procedure identity serialization failed: {error}")))?;
    Ok(sha256_bytes(&bytes))
}

pub fn to_normalized_process_ir(ir: &CantorProcessIr) -> Result<String, EvaluationFault> {
    validate_process_ir(ir)?;
    to_machine_form(ir)
}

pub fn from_normalized_process_ir(value: &str) -> Result<CantorProcessIr, EvaluationFault> {
    let ir: CantorProcessIr = from_machine_form(value)?;
    validate_process_ir(&ir)?;
    if to_machine_form(&ir)? != value {
        return Err(form_fault("Process IR is valid JSON but not normalized"));
    }
    Ok(ir)
}

fn validate_candidate(candidate: &ProcedureCandidate) -> Result<(), EvaluationFault> {
    if candidate.language_profile != CPPE_FORM_VERSION {
        return Err(form_fault("candidate uses an unsupported language profile"));
    }
    if candidate.lifecycle != ProcedureLifecycle::Proposed {
        return Err(form_fault("ProcedureCandidate lifecycle must be proposed"));
    }
    validate_text(
        "candidate purpose",
        &candidate.purpose,
        candidate.bounds.maximum_text_bytes,
    )?;
    if candidate.scope.is_empty() {
        return Err(form_fault("candidate scope cannot be empty"));
    }
    if candidate.scope.len() as u64 > candidate.bounds.maximum_collection_items {
        return Err(form_fault("candidate scope exceeds collection bound"));
    }
    for scope in &candidate.scope {
        validate_text(
            "candidate scope",
            scope,
            candidate.bounds.maximum_text_bytes,
        )?;
    }
    if candidate.source_text.is_some() == candidate.normalized_source_form.is_some() {
        return Err(form_fault(
            "candidate must contain exactly one source text or normalized source form",
        ));
    }
    validate_digest("candidate source digest", &candidate.source_digest)?;
    validate_bounds(&candidate.bounds)?;
    validate_effects(&candidate.effects)?;
    validate_schema_set(&candidate.schema_set, &candidate.bounds)?;
    if candidate.process_definitions.is_empty() {
        return Err(form_fault("candidate must declare at least one process"));
    }
    if candidate.process_definitions.len() as u64 > candidate.bounds.maximum_processes {
        return Err(form_fault("candidate process count exceeds its bound"));
    }
    let mut names = BTreeSet::new();
    for (key, process) in &candidate.process_definitions {
        if key != &process.process_definition_id {
            return Err(form_fault(
                "candidate process key differs from process identity",
            ));
        }
        if !names.insert(process.name.clone()) {
            return Err(form_fault("candidate process names are not unique"));
        }
        validate_process_definition(process, &candidate.bounds)?;
    }
    if let Some(source) = &candidate.source_text {
        validate_text(
            "candidate source",
            source,
            candidate.bounds.maximum_source_bytes,
        )?;
    }
    if let Some(source) = &candidate.normalized_source_form {
        validate_value_with_bounds(source, &candidate.bounds)?;
    }
    if compute_candidate_source_digest(candidate)? != candidate.source_digest {
        return Err(form_fault(
            "candidate source digest does not match its source",
        ));
    }
    if candidate.sop_anchors.len() as u64 > candidate.bounds.maximum_map_entries {
        return Err(form_fault("candidate SOP anchor set exceeds its bound"));
    }
    for (key, anchor) in &candidate.sop_anchors {
        if key != &anchor.anchor_id {
            return Err(form_fault("SOP anchor key differs from anchor identity"));
        }
        validate_text("SOP artifact version", &anchor.artifact_version, 256)?;
        validate_text(
            "SOP intended use",
            &anchor.intended_use,
            candidate.bounds.maximum_text_bytes,
        )?;
        validate_digest("SOP artifact digest", &anchor.artifact_digest)?;
    }
    Ok(())
}

fn validate_compiled_identity(
    identity: &crate::CompiledProcedureIdentity,
) -> Result<(), EvaluationFault> {
    validate_text("procedure version", &identity.procedure_version, 256)?;
    validate_text("language profile", &identity.language_profile, 256)?;
    validate_digest("canonical source digest", &identity.canonical_source_digest)?;
    validate_digest("IR digest", &identity.ir_digest)?;
    validate_digest("schema set digest", &identity.schema_set_digest)?;
    validate_digest("procedure digest", &identity.procedure_digest)?;
    if compute_compiled_procedure_digest(identity)? != identity.procedure_digest {
        return Err(form_fault(
            "compiled procedure digest does not match its identity fields",
        ));
    }
    Ok(())
}

fn validate_process_ir(ir: &CantorProcessIr) -> Result<(), EvaluationFault> {
    if ir.ir_version != CPPE_IR_VERSION {
        return Err(form_fault("unsupported Cantor Process IR version"));
    }
    validate_digest("IR source digest", &ir.source_digest)?;
    validate_bounds(&ir.bounds)?;
    validate_effects(&ir.effects)?;
    validate_schema_set(&ir.schema_set, &ir.bounds)?;
    if ir.process_definitions.is_empty() {
        return Err(form_fault("Process IR must contain at least one process"));
    }
    if ir.process_definitions.len() as u64 > ir.bounds.maximum_processes {
        return Err(form_fault("Process IR process count exceeds its bound"));
    }
    for (key, process) in &ir.process_definitions {
        if key != &process.process_definition_id {
            return Err(form_fault("Process IR process key differs from identity"));
        }
        validate_process_definition(process, &ir.bounds)?;
    }
    for value_type in ir.type_table.values() {
        validate_type_with_bounds(value_type, &ir.bounds, ir.bounds.maximum_call_depth)?;
    }
    for value in ir.constants.values() {
        validate_value_with_bounds(value, &ir.bounds)?;
    }
    if ir.type_table.len() as u64 > ir.bounds.maximum_map_entries
        || ir.constants.len() as u64 > ir.bounds.maximum_map_entries
        || ir.sop_anchors.len() as u64 > ir.bounds.maximum_map_entries
        || ir.source_map.len() as u64 > ir.bounds.maximum_map_entries
    {
        return Err(form_fault("Process IR table exceeds its map-entry bound"));
    }
    for (key, anchor) in &ir.sop_anchors {
        if key != &anchor.anchor_id {
            return Err(form_fault("Process IR anchor key differs from identity"));
        }
        validate_text(
            "SOP intended use",
            &anchor.intended_use,
            ir.bounds.maximum_text_bytes,
        )?;
        validate_digest("SOP artifact digest", &anchor.artifact_digest)?;
    }
    for (key, source_map) in &ir.source_map {
        if key != &source_map.source_map_id {
            return Err(form_fault("source-map key differs from record identity"));
        }
    }
    let computed = compute_process_ir_digest(ir)?;
    if computed != ir.ir_digest {
        return Err(form_fault(format!(
            "Process IR digest mismatch: expected {}, observed {}",
            digest_key(&computed),
            digest_key(&ir.ir_digest)
        )));
    }
    Ok(())
}

fn validate_bounds(bounds: &ProcedureBounds) -> Result<(), EvaluationFault> {
    let values = [
        bounds.maximum_source_bytes,
        bounds.maximum_text_bytes,
        bounds.maximum_value_bytes,
        bounds.maximum_collection_items,
        bounds.maximum_map_entries,
        bounds.maximum_processes,
        bounds.maximum_messages,
        bounds.maximum_queue_depth,
        bounds.maximum_events,
        bounds.maximum_event_queue_depth,
        bounds.maximum_call_depth,
        bounds.maximum_transitions,
        bounds.maximum_trace_events,
        bounds.maximum_memory_units,
    ];
    if values.contains(&0) {
        return Err(form_fault("all CPPE bounds must be positive"));
    }
    if bounds.maximum_call_depth > MAX_VALUE_DEPTH {
        return Err(form_fault(format!(
            "maximum call depth exceeds profile bound {MAX_VALUE_DEPTH}"
        )));
    }
    if bounds.maximum_text_bytes > bounds.maximum_value_bytes {
        return Err(form_fault("text bound exceeds whole-value byte bound"));
    }
    Ok(())
}

fn validate_effects(effects: &crate::ProcedureEffectDeclaration) -> Result<(), EvaluationFault> {
    if effects.effect_class != ProcedureEffectClass::Effectless {
        return Err(form_fault("first CPPE profile is effectless only"));
    }
    if effects.allowed_read_classes.is_empty() || effects.allowed_write_classes.is_empty() {
        return Err(form_fault(
            "effectless read and write declarations cannot be empty",
        ));
    }
    if effects.prohibited_operations != all_prohibited_operations() {
        return Err(form_fault(
            "effectless profile must retain the complete prohibited-operation set",
        ));
    }
    Ok(())
}

fn all_prohibited_operations() -> BTreeSet<crate::ProhibitedProcedureOperation> {
    use crate::ProhibitedProcedureOperation::*;
    BTreeSet::from([
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
    ])
}

fn validate_schema_set(
    schema_set: &ProcedureSchemaSet,
    bounds: &ProcedureBounds,
) -> Result<(), EvaluationFault> {
    validate_digest("schema-set digest", &schema_set.schema_set_digest)?;
    if compute_schema_set_digest(schema_set)? != schema_set.schema_set_digest {
        return Err(form_fault("schema-set digest does not match its members"));
    }
    if schema_set.schemas.len() as u64 > bounds.maximum_map_entries {
        return Err(form_fault("schema set exceeds map-entry bound"));
    }
    let mut seen_kinds = BTreeSet::new();
    for (key, schema) in &schema_set.schemas {
        if key != &schema.schema_id {
            return Err(form_fault("schema key differs from schema identity"));
        }
        seen_kinds.insert(schema.kind);
        validate_schema(schema, bounds)?;
    }
    let required_kinds = BTreeSet::from([
        SchemaKind::Input,
        SchemaKind::Output,
        SchemaKind::Message,
        SchemaKind::Event,
        SchemaKind::ProcessLocalState,
        SchemaKind::ProcedureState,
        SchemaKind::InvocationResult,
        SchemaKind::Fault,
    ]);
    if seen_kinds != required_kinds {
        return Err(form_fault(
            "schema set must cover every required first-profile schema kind",
        ));
    }
    Ok(())
}

fn validate_schema_set_unbounded(schema_set: &ProcedureSchemaSet) -> Result<(), EvaluationFault> {
    validate_digest("schema-set digest", &schema_set.schema_set_digest)?;
    if compute_schema_set_digest(schema_set)? != schema_set.schema_set_digest {
        return Err(form_fault("schema-set digest does not match its members"));
    }
    for (key, schema) in &schema_set.schemas {
        if key != &schema.schema_id {
            return Err(form_fault("schema key differs from schema identity"));
        }
        validate_text("schema version", &schema.schema_version, 256)?;
    }
    Ok(())
}

fn validate_schema(
    schema: &ProcedureSchema,
    bounds: &ProcedureBounds,
) -> Result<(), EvaluationFault> {
    validate_text("schema version", &schema.schema_version, 256)?;
    if !schema.closed {
        return Err(form_fault("first-profile schemas must be closed"));
    }
    if schema.fields.len() as u64 > bounds.maximum_map_entries
        || schema.tagged_variants.len() as u64 > bounds.maximum_map_entries
    {
        return Err(form_fault("schema member count exceeds map-entry bound"));
    }
    for (key, field) in &schema.fields {
        if key != &field.field_name {
            return Err(form_fault("schema field key differs from field name"));
        }
        validate_text("schema field name", &field.field_name, 256)?;
        validate_type_with_bounds(&field.value_type, bounds, bounds.maximum_call_depth)?;
    }
    for (key, variant) in &schema.tagged_variants {
        if key != &variant.tag {
            return Err(form_fault("tagged variant key differs from tag"));
        }
        validate_text("variant tag", &variant.tag, 256)?;
        validate_type_with_bounds(&variant.value_type, bounds, bounds.maximum_call_depth)?;
    }
    Ok(())
}

fn validate_type(value: &ProcedureType, depth: u64) -> Result<(), EvaluationFault> {
    if depth == 0 {
        return Err(form_fault(
            "procedure type nesting exceeds call-depth bound",
        ));
    }
    match value {
        ProcedureType::BoundedInteger { minimum, maximum } if minimum > maximum => {
            Err(form_fault("bounded integer minimum exceeds maximum"))
        }
        ProcedureType::BoundedDecimal {
            minimum,
            maximum,
            scale,
        } => {
            validate_decimal("decimal minimum", minimum)?;
            validate_decimal("decimal maximum", maximum)?;
            if decimal_fraction_digits(minimum) > *scale as usize
                || decimal_fraction_digits(maximum) > *scale as usize
            {
                return Err(form_fault("bounded decimal exceeds declared scale"));
            }
            if compare_canonical_decimals(minimum, maximum) == Ordering::Greater {
                return Err(form_fault("bounded decimal minimum exceeds maximum"));
            }
            Ok(())
        }
        ProcedureType::BoundedText { maximum_bytes } if *maximum_bytes == 0 => {
            Err(form_fault("bounded text maximum must be positive"))
        }
        ProcedureType::List {
            member,
            maximum_items,
        } => {
            if *maximum_items == 0 {
                return Err(form_fault("list bound must be positive"));
            }
            validate_type(member, depth - 1)
        }
        ProcedureType::OrderedMap {
            value,
            maximum_entries,
        } => {
            if *maximum_entries == 0 {
                return Err(form_fault("map bound must be positive"));
            }
            validate_type(value, depth - 1)
        }
        _ => Ok(()),
    }
}

fn validate_type_with_bounds(
    value: &ProcedureType,
    bounds: &ProcedureBounds,
    depth: u64,
) -> Result<(), EvaluationFault> {
    validate_type(value, depth)?;
    match value {
        ProcedureType::BoundedText { maximum_bytes }
            if *maximum_bytes > bounds.maximum_text_bytes =>
        {
            Err(form_fault("schema text type exceeds procedure text bound"))
        }
        ProcedureType::List {
            member,
            maximum_items,
        } => {
            if *maximum_items > bounds.maximum_collection_items {
                return Err(form_fault("schema list type exceeds collection bound"));
            }
            validate_type_with_bounds(member, bounds, depth - 1)
        }
        ProcedureType::OrderedMap {
            value,
            maximum_entries,
        } => {
            if *maximum_entries > bounds.maximum_map_entries {
                return Err(form_fault("schema map type exceeds map-entry bound"));
            }
            validate_type_with_bounds(value, bounds, depth - 1)
        }
        _ => Ok(()),
    }
}

fn validate_process_definition(
    process: &ProcessDefinition,
    bounds: &ProcedureBounds,
) -> Result<(), EvaluationFault> {
    validate_text("process name", &process.name, bounds.maximum_text_bytes)?;
    if process.control_regions.is_empty() {
        return Err(form_fault("process control-region map cannot be empty"));
    }
    if process.accepted_message_tags.len() as u64 > bounds.maximum_collection_items
        || process.emitted_message_tags.len() as u64 > bounds.maximum_collection_items
        || process.control_regions.len() as u64 > bounds.maximum_map_entries
    {
        return Err(form_fault(
            "process declaration exceeds its collection bound",
        ));
    }
    for tag in process
        .accepted_message_tags
        .iter()
        .chain(process.emitted_message_tags.iter())
    {
        validate_text("process message tag", tag, bounds.maximum_text_bytes)?;
    }
    if !process
        .control_regions
        .contains_key(&process.entry_region_ref)
    {
        return Err(form_fault("process entry region is missing"));
    }
    for terminal in &process.terminal_region_refs {
        let region = process
            .control_regions
            .get(terminal)
            .ok_or_else(|| form_fault(format!("terminal region {terminal} is missing")))?;
        if !region.terminal {
            return Err(form_fault(
                "terminal region reference targets nonterminal region",
            ));
        }
    }
    for (key, region) in &process.control_regions {
        if key != &region.region_id {
            return Err(form_fault(
                "control-region key differs from region identity",
            ));
        }
        validate_region(region, process, bounds)?;
    }
    validate_value_with_bounds(&process.initial_state, bounds)
}

fn validate_process_definition_unbounded(
    process: &ProcessDefinition,
) -> Result<(), EvaluationFault> {
    validate_text("process name", &process.name, MAX_PROFILE_TEXT_BYTES as u64)?;
    if process.control_regions.is_empty() {
        return Err(form_fault("process control-region map cannot be empty"));
    }
    Ok(())
}

fn validate_region(
    region: &ControlRegion,
    process: &ProcessDefinition,
    bounds: &ProcedureBounds,
) -> Result<(), EvaluationFault> {
    if region.instructions.is_empty() {
        return Err(form_fault("control region cannot be empty"));
    }
    if region.instructions.len() as u64 > bounds.maximum_transitions {
        return Err(form_fault("control region exceeds transition bound"));
    }
    for instruction in &region.instructions {
        validate_instruction(instruction, process, bounds)?;
    }
    Ok(())
}

fn validate_instruction(
    instruction: &ProcessInstruction,
    process: &ProcessDefinition,
    bounds: &ProcedureBounds,
) -> Result<(), EvaluationFault> {
    if instruction.bound_ref != bounds.bound_set_id {
        return Err(form_fault("instruction does not cite the active bound set"));
    }
    if instruction.operands.len() as u64 > bounds.maximum_collection_items {
        return Err(form_fault("instruction operand count exceeds bound"));
    }
    let mut operand_names = BTreeSet::new();
    for operand in &instruction.operands {
        validate_text("operand name", &operand.name, 256)?;
        if !operand_names.insert(operand.name.clone()) {
            return Err(form_fault("instruction operand names are not unique"));
        }
        validate_value_with_bounds(&operand.value, bounds)?;
    }
    for successor in &instruction.successor_region_refs {
        if !process.control_regions.contains_key(successor) {
            return Err(form_fault(format!(
                "instruction successor region {successor} is missing"
            )));
        }
    }
    Ok(())
}

fn validate_value(
    value: &ProcedureValue,
    byte_bound: u64,
    depth: u64,
) -> Result<(), EvaluationFault> {
    if depth == 0 {
        return Err(form_fault(
            "procedure value nesting exceeds call-depth bound",
        ));
    }
    let encoded = serde_json::to_vec(value)
        .map_err(|error| form_fault(format!("procedure value serialization failed: {error}")))?;
    if encoded.len() as u64 > byte_bound {
        return Err(form_fault("procedure value exceeds byte bound"));
    }
    match value {
        ProcedureValue::Decimal { canonical } => validate_decimal("decimal value", canonical),
        ProcedureValue::Text { value } => validate_text("text value", value, byte_bound),
        ProcedureValue::BytesDigest { value } => validate_digest("value digest", value),
        ProcedureValue::List { members } => {
            for member in members {
                validate_value(member, byte_bound, depth - 1)?;
            }
            Ok(())
        }
        ProcedureValue::OrderedMap { entries } => {
            for (key, member) in entries {
                validate_text("ordered-map key", key, 256)?;
                validate_value(member, byte_bound, depth - 1)?;
            }
            Ok(())
        }
        ProcedureValue::Record { fields } => {
            for (key, member) in fields {
                validate_text("record field", key, 256)?;
                validate_value(member, byte_bound, depth - 1)?;
            }
            Ok(())
        }
        ProcedureValue::TaggedUnion { tag, value } => {
            validate_text("tagged-union tag", tag, 256)?;
            validate_value(value, byte_bound, depth - 1)
        }
        _ => Ok(()),
    }
}

fn validate_value_with_bounds(
    value: &ProcedureValue,
    bounds: &ProcedureBounds,
) -> Result<(), EvaluationFault> {
    validate_value(value, bounds.maximum_value_bytes, bounds.maximum_call_depth)?;
    validate_value_collection_bounds(value, bounds, bounds.maximum_call_depth)
}

fn validate_value_collection_bounds(
    value: &ProcedureValue,
    bounds: &ProcedureBounds,
    depth: u64,
) -> Result<(), EvaluationFault> {
    if depth == 0 {
        return Err(form_fault(
            "procedure value nesting exceeds call-depth bound",
        ));
    }
    match value {
        ProcedureValue::Text { value } => {
            validate_text("text value", value, bounds.maximum_text_bytes)
        }
        ProcedureValue::List { members } => {
            if members.len() as u64 > bounds.maximum_collection_items {
                return Err(form_fault("list value exceeds collection-item bound"));
            }
            for member in members {
                validate_value_collection_bounds(member, bounds, depth - 1)?;
            }
            Ok(())
        }
        ProcedureValue::OrderedMap { entries } | ProcedureValue::Record { fields: entries } => {
            if entries.len() as u64 > bounds.maximum_map_entries {
                return Err(form_fault("map value exceeds map-entry bound"));
            }
            for member in entries.values() {
                validate_value_collection_bounds(member, bounds, depth - 1)?;
            }
            Ok(())
        }
        ProcedureValue::TaggedUnion { value, .. } => {
            validate_value_collection_bounds(value, bounds, depth - 1)
        }
        _ => Ok(()),
    }
}

fn validate_receipt_maps(forms: &ProcedureFormSet) -> Result<(), EvaluationFault> {
    validate_map(
        "validation receipt",
        &forms.validation_receipts,
        |v| &v.receipt_id,
        |v| {
            validate_digest(
                "validation candidate source digest",
                &v.candidate_source_digest,
            )?;
            validate_digest("validation receipt digest", &v.receipt_digest)
        },
    )?;
    validate_map(
        "compilation receipt",
        &forms.compilation_receipts,
        |v| &v.receipt_id,
        |v| {
            validate_digest(
                "compilation candidate source digest",
                &v.candidate_source_digest,
            )?;
            if v.disposition == PhaseDisposition::Passed && v.ir_ref.is_none() {
                return Err(form_fault("passed compilation receipt must name its IR"));
            }
            if v.disposition == PhaseDisposition::Passed && v.ir_digest.is_none() {
                return Err(form_fault(
                    "passed compilation receipt must bind its IR digest",
                ));
            }
            if v.disposition != PhaseDisposition::Passed
                && (v.ir_ref.is_some() || v.ir_digest.is_some())
            {
                return Err(form_fault(
                    "refused compilation cannot publish an IR reference",
                ));
            }
            if let Some(ir_digest) = &v.ir_digest {
                validate_digest("compilation IR digest", ir_digest)?;
            }
            validate_digest("compilation receipt digest", &v.receipt_digest)
        },
    )?;
    validate_map(
        "verification receipt",
        &forms.verification_receipts,
        |v| &v.receipt_id,
        |v| {
            validate_digest(
                "verification candidate source digest",
                &v.candidate_source_digest,
            )?;
            validate_digest("verified IR digest", &v.ir_digest)?;
            validate_digest("verified procedure digest", &v.compiled_procedure_digest)?;
            validate_digest("verified anchor-set digest", &v.anchor_set_digest)?;
            validate_digest(
                "verified effect-declaration digest",
                &v.effect_declaration_digest,
            )?;
            validate_digest("verified bounds digest", &v.bounds_digest)?;
            validate_digest("verification receipt digest", &v.receipt_digest)?;
            if compute_verification_receipt_digest(v)? != v.receipt_digest {
                return Err(form_fault("verification receipt digest mismatch"));
            }
            Ok(())
        },
    )?;
    validate_map(
        "admission disposition",
        &forms.admission_dispositions,
        |v| &v.disposition_id,
        |v| {
            validate_digest(
                "admission candidate source digest",
                &v.candidate_source_digest,
            )?;
            validate_digest("admission IR digest", &v.ir_digest)?;
            validate_digest("admission procedure digest", &v.procedure_digest)?;
            validate_digest("admission anchor-set digest", &v.anchor_set_digest)?;
            validate_digest(
                "admission effect-declaration digest",
                &v.effect_declaration_digest,
            )?;
            validate_digest("admission bounds digest", &v.bounds_digest)?;
            validate_digest("admission policy digest", &v.policy_digest)?;
            if v.decision != AdmissionDecision::Refuse && v.permitted_invocation_contexts.is_empty()
            {
                return Err(form_fault(
                    "admitted or qualified procedure needs an invocation context",
                ));
            }
            if v.decision != AdmissionDecision::Refuse && v.revocation_conditions.is_empty() {
                return Err(form_fault(
                    "admitted or qualified procedure needs a revocation condition",
                ));
            }
            if v.decision == AdmissionDecision::Refuse
                && (!v.permitted_invocation_contexts.is_empty()
                    || !v.revocation_conditions.is_empty())
            {
                return Err(form_fault(
                    "refused admission cannot publish invocation authority",
                ));
            }
            validate_digest("admission disposition digest", &v.disposition_digest)?;
            if compute_admission_disposition_digest(v)? != v.disposition_digest {
                return Err(form_fault("admission disposition digest mismatch"));
            }
            Ok(())
        },
    )?;
    validate_map(
        "catalogue receipt",
        &forms.catalogue_receipts,
        |v| &v.receipt_id,
        |v| {
            validate_digest("catalogue before digest", &v.catalogue_generation_before)?;
            validate_digest("catalogue procedure digest", &v.procedure_digest)?;
            validate_digest(
                "catalogue admission disposition digest",
                &v.admission_disposition_digest,
            )?;
            if let Some(after) = &v.catalogue_generation_after {
                validate_digest("catalogue after digest", after)?;
            }
            if v.disposition == PhaseDisposition::Passed && v.catalogue_generation_after.is_none() {
                return Err(form_fault(
                    "passed catalogue receipt needs an after generation",
                ));
            }
            validate_digest("catalogue receipt digest", &v.receipt_digest)?;
            if compute_catalogue_receipt_digest(v)? != v.receipt_digest {
                return Err(form_fault("catalogue receipt digest mismatch"));
            }
            Ok(())
        },
    )
}

fn validate_relations(forms: &ProcedureFormSet) -> Result<(), EvaluationFault> {
    for schema_set in forms.schema_sets.values() {
        let matching = forms
            .candidates
            .values()
            .map(|candidate| &candidate.schema_set)
            .chain(forms.process_irs.values().map(|ir| &ir.schema_set))
            .any(|nested| nested == schema_set);
        if !matching {
            return Err(form_fault(
                "standalone schema-set projection has no exact candidate or IR source",
            ));
        }
    }
    for process in forms.process_definitions.values() {
        let matching = forms
            .candidates
            .values()
            .filter_map(|candidate| {
                candidate
                    .process_definitions
                    .get(&process.process_definition_id)
            })
            .chain(
                forms
                    .process_irs
                    .values()
                    .filter_map(|ir| ir.process_definitions.get(&process.process_definition_id)),
            )
            .any(|nested| nested == process);
        if !matching {
            return Err(form_fault(
                "standalone process projection has no exact candidate or IR source",
            ));
        }
    }
    for identity in forms.compiled_procedures.values() {
        let candidate = forms
            .candidates
            .get(&identity.candidate_ref)
            .ok_or_else(|| form_fault("compiled identity references missing candidate"))?;
        let ir = forms
            .process_irs
            .get(&identity.ir_ref)
            .ok_or_else(|| form_fault("compiled identity references missing Process IR"))?;
        if identity.canonical_source_digest != candidate.source_digest
            || identity.ir_digest != ir.ir_digest
            || identity.compiler_ref != ir.compiler_ref
            || identity.schema_set_digest != ir.schema_set.schema_set_digest
            || identity.effect_class != ir.effects.effect_class
            || identity.bound_set_ref != ir.bounds.bound_set_id
        {
            return Err(form_fault(
                "compiled identity does not bind its exact candidate and IR",
            ));
        }
    }

    let mut known_processes: BTreeSet<SemanticId> =
        forms.process_definitions.keys().cloned().collect();
    for candidate in forms.candidates.values() {
        known_processes.extend(candidate.process_definitions.keys().cloned());
    }
    for ir in forms.process_irs.values() {
        known_processes.extend(ir.process_definitions.keys().cloned());
    }
    for state in forms.process_instances.values() {
        if !known_processes.contains(&state.definition_ref) {
            return Err(form_fault("process instance references missing definition"));
        }
    }
    for continuation in forms.continuations.values() {
        if !forms
            .process_instances
            .get(&continuation.process_state.state_id)
            .is_some_and(|state| state == &continuation.process_state)
        {
            return Err(form_fault(
                "continuation does not bind an exact supplied process-state generation",
            ));
        }
    }
    for session in forms.negotiation_sessions.values() {
        if !forms
            .negotiated_frames
            .get(&session.frame.frame_id)
            .is_some_and(|frame| frame == &session.frame)
        {
            return Err(form_fault(
                "negotiation session does not bind an exact frame projection",
            ));
        }
        for (participant_ref, participant) in &session.participants {
            if !forms
                .participants
                .get(participant_ref)
                .is_some_and(|known| known == participant)
            {
                return Err(form_fault(
                    "negotiation participant lacks exact aggregate projection",
                ));
            }
        }
    }
    for message in forms.messages.values() {
        let session = forms
            .negotiation_sessions
            .values()
            .find(|session| session.session_id == message.session_ref)
            .ok_or_else(|| form_fault("message references missing negotiation session"))?;
        if session.frame_generation != message.frame_generation {
            return Err(form_fault("message frame generation is stale"));
        }
        if !session.participants.contains_key(&message.sender_ref)
            || !session.participants.contains_key(&message.receiver_ref)
        {
            return Err(form_fault(
                "message sender or receiver is absent from session",
            ));
        }
        if !session
            .participants
            .get(&message.sender_ref)
            .is_some_and(|participant| participant.permitted_message_kinds.contains(&message.kind))
        {
            return Err(form_fault("message kind is not permitted for its sender"));
        }
    }
    for pass in forms.token_ring_passes.values() {
        let session = forms
            .negotiation_sessions
            .values()
            .find(|session| session.session_id == pass.session_ref)
            .ok_or_else(|| form_fault("token-ring pass references missing session"))?;
        if session.frame_generation != pass.frame_generation
            || !session
                .required_participant_refs
                .contains(&pass.participant_ref)
        {
            return Err(form_fault(
                "token-ring pass has stale frame or nonrequired participant",
            ));
        }
    }
    for receipt in forms.validation_receipts.values() {
        if !forms
            .candidates
            .get(&receipt.candidate_ref)
            .is_some_and(|candidate| candidate.source_digest == receipt.candidate_source_digest)
        {
            return Err(form_fault(
                "validation receipt references missing or substituted candidate content",
            ));
        }
    }
    for receipt in forms.compilation_receipts.values() {
        if !forms.candidates.contains_key(&receipt.candidate_ref)
            || !forms
                .validation_receipts
                .contains_key(&receipt.validation_receipt_ref)
        {
            return Err(form_fault(
                "compilation receipt has missing predecessor evidence",
            ));
        }
        if !forms
            .candidates
            .get(&receipt.candidate_ref)
            .is_some_and(|candidate| candidate.source_digest == receipt.candidate_source_digest)
        {
            return Err(form_fault(
                "compilation receipt does not bind exact candidate content",
            ));
        }
        if let Some(ir_ref) = &receipt.ir_ref
            && !forms.process_irs.get(ir_ref).is_some_and(|ir| {
                receipt
                    .ir_digest
                    .as_ref()
                    .is_some_and(|digest| digest == &ir.ir_digest)
            })
        {
            return Err(form_fault(
                "compilation receipt references missing or substituted Process IR",
            ));
        }
    }
    for receipt in forms.verification_receipts.values() {
        let Some(candidate) = forms.candidates.get(&receipt.candidate_ref) else {
            return Err(form_fault(
                "verification receipt has missing predecessor evidence",
            ));
        };
        let Some(compilation) = forms
            .compilation_receipts
            .get(&receipt.compilation_receipt_ref)
        else {
            return Err(form_fault(
                "verification receipt has missing predecessor evidence",
            ));
        };
        let Some(ir) = forms.process_irs.get(&receipt.ir_ref) else {
            return Err(form_fault(
                "verification receipt references missing Process IR",
            ));
        };
        let Some(procedure) = forms
            .compiled_procedures
            .get(&receipt.compiled_procedure_ref)
        else {
            return Err(form_fault(
                "verification receipt references missing compiled procedure",
            ));
        };
        if candidate.source_digest != receipt.candidate_source_digest
            || compilation.candidate_ref != receipt.candidate_ref
            || compilation.candidate_source_digest != receipt.candidate_source_digest
            || compilation.compiler_ref != receipt.compiler_ref
            || compilation.ir_ref.as_ref() != Some(&receipt.ir_ref)
            || compilation.ir_digest.as_ref() != Some(&receipt.ir_digest)
            || ir.ir_digest != receipt.ir_digest
            || ir.compiler_ref != receipt.compiler_ref
            || procedure.ir_ref != receipt.ir_ref
            || procedure.ir_digest != receipt.ir_digest
            || procedure.procedure_digest != receipt.compiled_procedure_digest
            || procedure.bound_set_ref != receipt.bound_set_ref
            || compute_anchor_set_digest(&ir.sop_anchors)? != receipt.anchor_set_digest
            || compute_effect_declaration_digest(&ir.effects)? != receipt.effect_declaration_digest
            || compute_procedure_bounds_digest(&ir.bounds)? != receipt.bounds_digest
        {
            return Err(form_fault(
                "verification receipt does not bind exact candidate, compiler, IR, and procedure content",
            ));
        }
        if receipt.disposition == PhaseDisposition::Passed
            && compilation.disposition != PhaseDisposition::Passed
        {
            return Err(form_fault(
                "passed verification cannot follow a refused or faulted compilation",
            ));
        }
    }
    for disposition in forms.admission_dispositions.values() {
        let Some(candidate) = forms.candidates.get(&disposition.candidate_ref) else {
            return Err(form_fault(
                "admission disposition has missing predecessor evidence",
            ));
        };
        let Some(validation) = forms
            .validation_receipts
            .get(&disposition.validation_receipt_ref)
        else {
            return Err(form_fault(
                "admission disposition has missing validation evidence",
            ));
        };
        let Some(compilation) = forms
            .compilation_receipts
            .get(&disposition.compilation_receipt_ref)
        else {
            return Err(form_fault(
                "admission disposition has missing compilation evidence",
            ));
        };
        let Some(verification) = forms
            .verification_receipts
            .get(&disposition.verification_receipt_ref)
        else {
            return Err(form_fault(
                "admission disposition has missing verification evidence",
            ));
        };
        let Some(ir) = forms.process_irs.get(&disposition.ir_ref) else {
            return Err(form_fault(
                "admission disposition references missing Process IR",
            ));
        };
        let Some(procedure) = forms.compiled_procedures.get(&disposition.procedure_ref) else {
            return Err(form_fault(
                "admission disposition references missing compiled procedure",
            ));
        };
        if candidate.source_digest != disposition.candidate_source_digest
            || validation.candidate_ref != disposition.candidate_ref
            || validation.candidate_source_digest != disposition.candidate_source_digest
            || compilation.validation_receipt_ref != disposition.validation_receipt_ref
            || verification.compilation_receipt_ref != disposition.compilation_receipt_ref
            || verification.receipt_id != disposition.verification_receipt_ref
            || verification.compiler_ref != disposition.compiler_ref
            || verification.ir_ref != disposition.ir_ref
            || verification.ir_digest != disposition.ir_digest
            || verification.compiled_procedure_ref != disposition.procedure_ref
            || verification.compiled_procedure_digest != disposition.procedure_digest
            || verification.anchor_set_digest != disposition.anchor_set_digest
            || verification.effect_declaration_digest != disposition.effect_declaration_digest
            || verification.bound_set_ref != disposition.bound_set_ref
            || verification.bounds_digest != disposition.bounds_digest
            || ir.ir_digest != disposition.ir_digest
            || procedure.procedure_digest != disposition.procedure_digest
        {
            return Err(form_fault(
                "admission disposition does not bind exact source, compiler, IR, verification, anchor, effect, and bound content",
            ));
        }
        if disposition.decision != AdmissionDecision::Refuse
            && (validation.disposition != PhaseDisposition::Passed
                || compilation.disposition != PhaseDisposition::Passed
                || verification.disposition != PhaseDisposition::Passed)
        {
            return Err(form_fault(
                "admission authority requires passed validation, compilation, and verification",
            ));
        }
    }
    for receipt_set in forms.phase_receipt_sets.values() {
        if !forms.candidates.contains_key(&receipt_set.candidate_ref)
            || !forms
                .validation_receipts
                .contains_key(&receipt_set.validation_receipt_ref)
        {
            return Err(form_fault(
                "phase receipt set lacks candidate or validation receipt",
            ));
        }
        if let Some(compilation) = &receipt_set.compilation_receipt_ref
            && !forms.compilation_receipts.contains_key(compilation)
        {
            return Err(form_fault(
                "phase receipt set references missing compilation receipt",
            ));
        }
        for verification in &receipt_set.verification_receipt_refs {
            if !forms.verification_receipts.contains_key(verification) {
                return Err(form_fault(
                    "phase receipt set references missing verification receipt",
                ));
            }
        }
        if let Some(admission) = &receipt_set.admission_disposition_ref
            && !forms.admission_dispositions.contains_key(admission)
        {
            return Err(form_fault(
                "phase receipt set references missing admission disposition",
            ));
        }
    }
    for receipt in forms.catalogue_receipts.values() {
        let Some(procedure) = forms.compiled_procedures.get(&receipt.procedure_ref) else {
            return Err(form_fault(
                "catalogue receipt lacks procedure or admission evidence",
            ));
        };
        let Some(admission) = forms
            .admission_dispositions
            .get(&receipt.admission_disposition_ref)
        else {
            return Err(form_fault(
                "catalogue receipt lacks procedure or admission evidence",
            ));
        };
        if procedure.procedure_digest != receipt.procedure_digest
            || admission.procedure_ref != receipt.procedure_ref
            || admission.procedure_digest != receipt.procedure_digest
            || admission.disposition_digest != receipt.admission_disposition_digest
        {
            return Err(form_fault(
                "catalogue receipt does not bind exact procedure and admission content",
            ));
        }
        if let Some(after) = &receipt.catalogue_generation_after {
            let key = digest_key(after);
            if !forms
                .catalogues_by_generation_digest
                .get(&key)
                .is_some_and(|catalogue| {
                    catalogue
                        .entries
                        .get(&receipt.procedure_ref)
                        .is_some_and(|entry| {
                            entry.procedure_digest == receipt.procedure_digest
                                && entry.admission_disposition_ref
                                    == receipt.admission_disposition_ref
                                && entry.admission_disposition_digest
                                    == receipt.admission_disposition_digest
                        })
                })
            {
                return Err(form_fault(
                    "passed catalogue receipt lacks exact after-state projection",
                ));
            }
        }
    }
    for catalogue in forms.catalogues_by_generation_digest.values() {
        for entry in catalogue.entries.values() {
            let Some(procedure) = forms.compiled_procedures.get(&entry.procedure_ref) else {
                return Err(form_fault(
                    "catalogue entry lacks procedure or admission evidence",
                ));
            };
            let Some(admission) = forms
                .admission_dispositions
                .get(&entry.admission_disposition_ref)
            else {
                return Err(form_fault(
                    "catalogue entry lacks procedure or admission evidence",
                ));
            };
            if procedure.procedure_digest != entry.procedure_digest
                || admission.procedure_ref != entry.procedure_ref
                || admission.procedure_digest != entry.procedure_digest
                || admission.disposition_digest != entry.admission_disposition_digest
            {
                return Err(form_fault(
                    "catalogue entry does not bind exact procedure and admission content",
                ));
            }
        }
    }
    for request in forms.invocation_requests.values() {
        let Some(procedure) = forms
            .compiled_procedures
            .get(&request.admitted_procedure_ref)
        else {
            return Err(form_fault(
                "invocation request lacks compiled or admission identity",
            ));
        };
        let Some(admission) = forms
            .admission_dispositions
            .get(&request.admission_disposition_ref)
        else {
            return Err(form_fault(
                "invocation request lacks compiled or admission identity",
            ));
        };
        if procedure.procedure_digest != request.procedure_digest
            || procedure.schema_set_digest != request.schema_set_digest
            || admission.procedure_ref != request.admitted_procedure_ref
            || admission.procedure_digest != request.procedure_digest
            || admission.disposition_digest != request.admission_disposition_digest
            || admission.anchor_set_digest != request.sop_anchor_set_digest
            || admission.policy_ref != request.policy_ref
            || admission.policy_digest != request.policy_digest
        {
            return Err(form_fault(
                "invocation request does not pin exact procedure, schema, anchors, admission, and policy content",
            ));
        }
        let catalogue_key = digest_key(&request.catalogue_generation_digest);
        if !forms
            .catalogues_by_generation_digest
            .get(&catalogue_key)
            .and_then(|catalogue| catalogue.entries.get(&request.admitted_procedure_ref))
            .is_some_and(|entry| {
                entry.status == CatalogueStatus::Active
                    && entry.procedure_digest == request.procedure_digest
                    && entry.admission_disposition_ref == request.admission_disposition_ref
                    && entry.admission_disposition_digest == request.admission_disposition_digest
            })
        {
            return Err(form_fault(
                "invocation request lacks an exact active catalogue generation",
            ));
        }
    }
    for result in forms.invocation_results.values() {
        let Some(request) = forms.invocation_requests.get(&result.invocation_ref) else {
            return Err(form_fault("invocation result references missing request"));
        };
        if result.procedure_ref != request.admitted_procedure_ref
            || result.semantic_trace.retention_policy_ref != request.retention_policy_ref
            || result.consumed_budget.steps > request.budgets.step_limit
            || result.consumed_budget.memory_units > request.budgets.memory_unit_limit
            || result.consumed_budget.messages > request.budgets.message_limit
            || result.consumed_budget.trace_events > request.budgets.trace_event_limit
        {
            return Err(form_fault(
                "invocation result does not bind its request or exceeds request budgets",
            ));
        }
    }
    Ok(())
}

fn validate_map<T, F, V>(
    label: &str,
    values: &BTreeMap<SemanticId, T>,
    identity: F,
    validate: V,
) -> Result<(), EvaluationFault>
where
    F: Fn(&T) -> &SemanticId,
    V: Fn(&T) -> Result<(), EvaluationFault>,
{
    for (key, value) in values {
        if key != identity(value) {
            return Err(form_fault(format!(
                "{label} map key differs from record identity"
            )));
        }
        validate(value)?;
    }
    Ok(())
}

fn validate_digest(label: &str, digest: &ContentDigest) -> Result<(), EvaluationFault> {
    validate_text(&format!("{label} algorithm"), &digest.algorithm, 64)?;
    validate_text(&format!("{label} value"), &digest.value, 512)
}

fn digest_key(digest: &ContentDigest) -> String {
    format!("{}:{}", digest.algorithm, digest.value)
}

fn validate_text(label: &str, value: &str, maximum_bytes: u64) -> Result<(), EvaluationFault> {
    if value.trim().is_empty() {
        return Err(form_fault(format!("{label} cannot be blank")));
    }
    if value.len() as u64 > maximum_bytes {
        return Err(form_fault(format!("{label} exceeds {maximum_bytes} bytes")));
    }
    Ok(())
}

fn validate_decimal(label: &str, value: &str) -> Result<(), EvaluationFault> {
    validate_text(label, value, 256)?;
    let bytes = value.as_bytes();
    let start = usize::from(bytes.first() == Some(&b'-'));
    if start == bytes.len()
        || bytes[start..]
            .iter()
            .any(|byte| !byte.is_ascii_digit() && *byte != b'.')
        || bytes[start..].iter().filter(|byte| **byte == b'.').count() > 1
        || value.starts_with('+')
        || value.contains('e')
        || value.contains('E')
    {
        return Err(form_fault(format!("{label} is not a canonical decimal")));
    }
    let magnitude = &value[start..];
    if (magnitude.starts_with('0') && magnitude.len() > 1 && !magnitude.starts_with("0."))
        || magnitude.ends_with('.')
        || magnitude.starts_with('.')
        || value == "-0"
    {
        return Err(form_fault(format!("{label} is not a canonical decimal")));
    }
    Ok(())
}

fn decimal_fraction_digits(value: &str) -> usize {
    value
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len())
}

fn compare_canonical_decimals(left: &str, right: &str) -> Ordering {
    let left_negative = left.starts_with('-');
    let right_negative = right.starts_with('-');
    if left_negative != right_negative {
        return if left_negative {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let left_magnitude = left.trim_start_matches('-');
    let right_magnitude = right.trim_start_matches('-');
    let (left_integer, left_fraction) = left_magnitude
        .split_once('.')
        .unwrap_or((left_magnitude, ""));
    let (right_integer, right_fraction) = right_magnitude
        .split_once('.')
        .unwrap_or((right_magnitude, ""));
    let magnitude_order = left_integer
        .len()
        .cmp(&right_integer.len())
        .then_with(|| left_integer.cmp(right_integer))
        .then_with(|| {
            let width = left_fraction.len().max(right_fraction.len());
            let mut left_padded = left_fraction.to_owned();
            let mut right_padded = right_fraction.to_owned();
            left_padded.extend(std::iter::repeat_n('0', width - left_fraction.len()));
            right_padded.extend(std::iter::repeat_n('0', width - right_fraction.len()));
            left_padded.cmp(&right_padded)
        });
    if left_negative {
        magnitude_order.reverse()
    } else {
        magnitude_order
    }
}

fn form_record_count(forms: &ProcedureFormSet) -> usize {
    forms.candidates.len()
        + forms.compiled_procedures.len()
        + forms.schema_sets.len()
        + forms.process_definitions.len()
        + forms.process_irs.len()
        + forms.process_instances.len()
        + forms.continuations.len()
        + forms.process_steps.len()
        + forms.participants.len()
        + forms.messages.len()
        + forms.negotiated_frames.len()
        + forms.negotiation_sessions.len()
        + forms.token_ring_passes.len()
        + forms.validation_receipts.len()
        + forms.compilation_receipts.len()
        + forms.verification_receipts.len()
        + forms.admission_dispositions.len()
        + forms.catalogue_receipts.len()
        + forms.revocations.len()
        + forms.phase_receipt_sets.len()
        + forms.catalogues_by_generation_digest.len()
        + forms.invocation_requests.len()
        + forms.invocation_results.len()
        + forms.semantic_traces.len()
        + forms.faults.len()
}

fn form_fault(message: impl Into<String>) -> EvaluationFault {
    EvaluationFault::new(FaultKind::MachineForm, message)
}
