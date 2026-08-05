//! Deterministic normalized-form compiler for CPPE-I03.
//!
//! Compilation assembles an already validated machine-form candidate into the
//! canonical Process IR. It does not parse text, verify, admit, catalogue,
//! schedule, interpret, invoke, or perform effects.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    CPPE_FORM_VERSION, CPPE_IR_VERSION, CantorProcessIr, CompilationReceipt,
    CompiledProcedureIdentity, ContentDigest, EvaluationFault, PhaseDisposition,
    ProcedureCandidate, ProcedureFormSet, ProcedureType, ReceiptEvidence, SemanticId,
    SourceMapEntry, ValidationReceipt, compute_compiled_procedure_digest,
    compute_process_ir_digest, sha256_bytes, validate_procedure_forms,
};

pub const CPPE_COMPILER_ID: &str = "cantor-process-compiler/0.1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilationOutcome {
    pub compilation_receipt: CompilationReceipt,
    pub process_ir: Option<CantorProcessIr>,
    pub compiled_procedure: Option<CompiledProcedureIdentity>,
}

pub fn compile_procedure_candidate(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
) -> Result<CompilationOutcome, EvaluationFault> {
    let compiler_ref = SemanticId::new(CPPE_COMPILER_ID)?;
    let attempt_digest = compilation_attempt_digest(candidate, validation_receipt, &compiler_ref)?;

    if let Err(reason) = validate_validation_receipt(candidate, validation_receipt) {
        return refused_outcome(
            candidate,
            validation_receipt,
            &compiler_ref,
            &attempt_digest,
            reason.message,
        );
    }

    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(candidate.candidate_id.clone(), candidate.clone());
    if let Err(reason) = validate_procedure_forms(&forms) {
        return refused_outcome(
            candidate,
            validation_receipt,
            &compiler_ref,
            &attempt_digest,
            reason.message,
        );
    }
    if candidate.source_text.is_some() {
        return refused_outcome(
            candidate,
            validation_receipt,
            &compiler_ref,
            &attempt_digest,
            "textual procedure source has no parser in CPPE-I03".to_owned(),
        );
    }

    let ir_id = derived_id("cppe:ir", &attempt_digest)?;
    let type_table = derive_type_table(candidate);
    let source_map = derive_source_map(candidate)?;
    let mut process_ir = CantorProcessIr {
        ir_id: ir_id.clone(),
        ir_version: CPPE_IR_VERSION.to_owned(),
        ir_digest: empty_sha256(),
        source_digest: candidate.source_digest.clone(),
        compiler_ref: compiler_ref.clone(),
        type_table,
        schema_set: candidate.schema_set.clone(),
        constants: BTreeMap::new(),
        sop_anchors: candidate.sop_anchors.clone(),
        process_definitions: candidate.process_definitions.clone(),
        effects: candidate.effects.clone(),
        bounds: candidate.bounds.clone(),
        source_map,
    };
    process_ir.ir_digest = compute_process_ir_digest(&process_ir)?;

    let procedure_seed = sha256_bytes(
        serde_json::to_string(&(
            &candidate.candidate_id,
            &candidate.source_digest,
            &compiler_ref,
            &process_ir.ir_id,
            &process_ir.ir_digest,
        ))
        .map_err(machine_fault)?
        .as_bytes(),
    );
    let mut compiled_procedure = CompiledProcedureIdentity {
        procedure_id: derived_id("cppe:procedure", &procedure_seed)?,
        procedure_version: "0.1".to_owned(),
        predecessor_procedure_refs: BTreeSet::new(),
        candidate_ref: candidate.candidate_id.clone(),
        canonical_source_digest: candidate.source_digest.clone(),
        compiler_ref: compiler_ref.clone(),
        language_profile: CPPE_FORM_VERSION.to_owned(),
        ir_ref: process_ir.ir_id.clone(),
        ir_digest: process_ir.ir_digest.clone(),
        schema_set_digest: process_ir.schema_set.schema_set_digest.clone(),
        effect_class: process_ir.effects.effect_class,
        bound_set_ref: process_ir.bounds.bound_set_id.clone(),
        procedure_digest: empty_sha256(),
    };
    compiled_procedure.procedure_digest = compute_compiled_procedure_digest(&compiled_procedure)?;

    let cost_estimate = cost_estimate(candidate, &process_ir);
    let mut compilation_receipt = CompilationReceipt {
        receipt_id: derived_id("cppe:compilation-receipt", &attempt_digest)?,
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        validation_receipt_ref: validation_receipt.receipt_id.clone(),
        compiler_ref,
        ir_ref: Some(process_ir.ir_id.clone()),
        ir_digest: Some(process_ir.ir_digest.clone()),
        disposition: PhaseDisposition::Passed,
        cost_estimate,
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([validation_receipt.receipt_id.clone()]),
            residuals: BTreeSet::from([
                "verification not performed".to_owned(),
                "Observer admission not performed".to_owned(),
            ]),
            diagnostics: BTreeSet::from([
                "compiled from normalized CPPE machine form".to_owned(),
                "textual syntax parser absent".to_owned(),
            ]),
        },
        receipt_digest: empty_sha256(),
    };
    compilation_receipt.receipt_digest = compute_compilation_receipt_digest(&compilation_receipt)?;

    Ok(CompilationOutcome {
        compilation_receipt,
        process_ir: Some(process_ir),
        compiled_procedure: Some(compiled_procedure),
    })
}

pub fn compute_validation_receipt_digest(
    receipt: &ValidationReceipt,
) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = receipt.clone();
    digest_body.receipt_digest = empty_sha256();
    digest_serialized(&digest_body, "validation receipt")
}

pub fn compute_compilation_receipt_digest(
    receipt: &CompilationReceipt,
) -> Result<ContentDigest, EvaluationFault> {
    let mut digest_body = receipt.clone();
    digest_body.receipt_digest = empty_sha256();
    digest_serialized(&digest_body, "compilation receipt")
}

fn validate_validation_receipt(
    candidate: &ProcedureCandidate,
    receipt: &ValidationReceipt,
) -> Result<(), EvaluationFault> {
    if receipt.candidate_ref != candidate.candidate_id
        || receipt.candidate_source_digest != candidate.source_digest
    {
        return Err(EvaluationFault::new(
            crate::FaultKind::MachineForm,
            "validation receipt names a different candidate",
        ));
    }
    if receipt.profile != CPPE_FORM_VERSION {
        return Err(EvaluationFault::new(
            crate::FaultKind::MachineForm,
            "validation receipt uses an unsupported profile",
        ));
    }
    if receipt.disposition != PhaseDisposition::Passed {
        return Err(EvaluationFault::new(
            crate::FaultKind::MachineForm,
            "compiler requires a passed validation receipt",
        ));
    }
    if compute_validation_receipt_digest(receipt)? != receipt.receipt_digest {
        return Err(EvaluationFault::new(
            crate::FaultKind::MachineForm,
            "validation receipt digest mismatch",
        ));
    }
    Ok(())
}

fn refused_outcome(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compiler_ref: &SemanticId,
    attempt_digest: &ContentDigest,
    diagnostic: String,
) -> Result<CompilationOutcome, EvaluationFault> {
    let mut receipt = CompilationReceipt {
        receipt_id: derived_id("cppe:compilation-receipt", attempt_digest)?,
        candidate_ref: candidate.candidate_id.clone(),
        candidate_source_digest: candidate.source_digest.clone(),
        validation_receipt_ref: validation_receipt.receipt_id.clone(),
        compiler_ref: compiler_ref.clone(),
        ir_ref: None,
        ir_digest: None,
        disposition: PhaseDisposition::Refused,
        cost_estimate: BTreeMap::new(),
        evidence: ReceiptEvidence {
            evidence_refs: BTreeSet::from([validation_receipt.receipt_id.clone()]),
            residuals: BTreeSet::from([
                "candidate preserved without compiled successor".to_owned(),
                "verification and admission not entered".to_owned(),
            ]),
            diagnostics: BTreeSet::from([diagnostic]),
        },
        receipt_digest: empty_sha256(),
    };
    receipt.receipt_digest = compute_compilation_receipt_digest(&receipt)?;
    Ok(CompilationOutcome {
        compilation_receipt: receipt,
        process_ir: None,
        compiled_procedure: None,
    })
}

fn compilation_attempt_digest(
    candidate: &ProcedureCandidate,
    validation_receipt: &ValidationReceipt,
    compiler_ref: &SemanticId,
) -> Result<ContentDigest, EvaluationFault> {
    let bytes = serde_json::to_vec(&(
        &candidate.candidate_id,
        &candidate.source_digest,
        &validation_receipt.receipt_id,
        &validation_receipt.receipt_digest,
        compiler_ref,
        CPPE_FORM_VERSION,
        CPPE_IR_VERSION,
    ))
    .map_err(machine_fault)?;
    Ok(sha256_bytes(&bytes))
}

fn derive_type_table(candidate: &ProcedureCandidate) -> BTreeMap<String, ProcedureType> {
    let mut table = BTreeMap::new();
    for schema in candidate.schema_set.schemas.values() {
        for field in schema.fields.values() {
            table.insert(
                format!("{}.field.{}", schema.schema_id, field.field_name),
                field.value_type.clone(),
            );
        }
        for variant in schema.tagged_variants.values() {
            table.insert(
                format!("{}.variant.{}", schema.schema_id, variant.tag),
                variant.value_type.clone(),
            );
        }
    }
    table
}

fn derive_source_map(
    candidate: &ProcedureCandidate,
) -> Result<BTreeMap<SemanticId, SourceMapEntry>, EvaluationFault> {
    let mut source_map = BTreeMap::new();
    for process in candidate.process_definitions.values() {
        for region in process.control_regions.values() {
            for instruction in &region.instructions {
                let seed = sha256_bytes(
                    serde_json::to_string(&(
                        &candidate.source_digest,
                        &process.process_definition_id,
                        &region.region_id,
                        &instruction.instruction_id,
                        &instruction.source_span_ref,
                    ))
                    .map_err(machine_fault)?
                    .as_bytes(),
                );
                let source_map_id = derived_id("cppe:source-map", &seed)?;
                source_map.insert(
                    source_map_id.clone(),
                    SourceMapEntry {
                        source_map_id,
                        source_span_ref: instruction.source_span_ref.clone(),
                        ir_subject_ref: instruction.instruction_id.clone(),
                    },
                );
            }
        }
    }
    Ok(source_map)
}

fn cost_estimate(candidate: &ProcedureCandidate, ir: &CantorProcessIr) -> BTreeMap<String, u64> {
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
    BTreeMap::from([
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
    ])
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
