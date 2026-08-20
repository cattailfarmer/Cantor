//! Pure adapter from seeded semantic-compiler forms to the existing CPPE compiler.
//!
//! This module consumes already-normalized and already-validated machine forms.
//! It does not author, parse, verify, admit, install, load, invoke, or execute a
//! procedure and grants no external-effect authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    COMPILER_NON_AUTHORITY, CandidateCompilationPlan, CompilerBackendKind, CompilerCapability,
    SemanticCompilerFormFault, SemanticCompilerFormFaultKind, SemanticCompilerValidation, SopSeed,
    TypedSopIr, bounded_set, digest_form, exact_non_authority, exact_profile, form_fault,
    normalize, require_digest, validate_candidate_compilation_plan, validate_digest,
};
use crate::{
    CPPE_FORM_VERSION, CompilationOutcome, ContentDigest, PhaseDisposition, ProcedureCandidate,
    ProcedureFormSet, ProcedureLifecycle, SemanticId, ValidationReceipt,
    compile_procedure_candidate, compute_candidate_source_digest,
    compute_compilation_receipt_digest, compute_validation_receipt_digest,
    validate_procedure_forms,
};

pub const ATTENTION_PROCEDURE_BACKEND_REQUEST_PROFILE: &str =
    "cantor-attention-procedure-backend-request/0.1";
pub const ATTENTION_PROCEDURE_BACKEND_PROJECTION_PROFILE: &str =
    "cantor-attention-procedure-backend-projection/0.1";

const PROJECTION_DOMAIN: &str = "cantor.semantic-compiler.attention-procedure-projection.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionProcedureBackendRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub candidate: ProcedureCandidate,
    pub validation_receipt: ValidationReceipt,
    pub semantic_node_anchor_map: BTreeMap<SemanticId, SemanticId>,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionProcedureBackendProjection {
    pub profile: String,
    pub request_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub plan_ref: SemanticId,
    pub plan_digest: ContentDigest,
    pub ir_ref: SemanticId,
    pub ir_digest: ContentDigest,
    pub candidate_ref: SemanticId,
    pub candidate_source_digest: ContentDigest,
    pub validation_receipt_ref: SemanticId,
    pub compilation: CompilationOutcome,
    pub unresolved_account: BTreeSet<String>,
    pub non_authority: String,
    pub projection_digest: ContentDigest,
}

pub fn attention_procedure_backend_projection_digest(
    projection: &AttentionProcedureBackendProjection,
) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        PROJECTION_DOMAIN,
        &(
            &projection.profile,
            &projection.request_id,
            &projection.seed_ref,
            &projection.seed_digest,
            &projection.plan_ref,
            &projection.plan_digest,
            &projection.ir_ref,
            &projection.ir_digest,
            &projection.candidate_ref,
            &projection.candidate_source_digest,
            &projection.validation_receipt_ref,
            &projection.compilation,
            &projection.unresolved_account,
            &projection.non_authority,
        ),
    )
}

pub fn project_attention_procedure_backend(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &AttentionProcedureBackendRequest,
) -> SemanticCompilerValidation<AttentionProcedureBackendProjection> {
    validate_attention_backend_request(seed, ir, plan, request)?;
    let compilation = compile_procedure_candidate(&request.candidate, &request.validation_receipt)
        .map_err(|error| compiler_fault("request.compilation", error.to_string()))?;
    validate_compilation_outcome(request, &compilation)?;

    let mut projection = AttentionProcedureBackendProjection {
        profile: ATTENTION_PROCEDURE_BACKEND_PROJECTION_PROFILE.to_owned(),
        request_id: request.request_id.clone(),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        plan_ref: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest.clone(),
        candidate_ref: request.candidate.candidate_id.clone(),
        candidate_source_digest: request.candidate.source_digest.clone(),
        validation_receipt_ref: request.validation_receipt.receipt_id.clone(),
        compilation,
        unresolved_account: request.unresolved_account.clone(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        projection_digest: empty_digest(),
    };
    projection.projection_digest = attention_procedure_backend_projection_digest(&projection)?;
    validate_attention_procedure_backend_projection(seed, ir, plan, request, &projection)?;
    Ok(projection)
}

pub fn validate_attention_procedure_backend_projection(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &AttentionProcedureBackendRequest,
    projection: &AttentionProcedureBackendProjection,
) -> SemanticCompilerValidation {
    validate_attention_backend_request(seed, ir, plan, request)?;
    exact_profile(
        &projection.profile,
        ATTENTION_PROCEDURE_BACKEND_PROJECTION_PROFILE,
        "projection.profile",
    )?;
    if projection.request_id != request.request_id
        || projection.seed_ref != seed.seed_id
        || projection.seed_digest != seed.seed_digest
        || projection.plan_ref != plan.plan_id
        || projection.plan_digest != plan.plan_digest
        || projection.ir_ref != ir.ir_id
        || projection.ir_digest != ir.ir_digest
        || projection.candidate_ref != request.candidate.candidate_id
        || projection.candidate_source_digest != request.candidate.source_digest
        || projection.validation_receipt_ref != request.validation_receipt.receipt_id
        || projection.unresolved_account != request.unresolved_account
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "projection.lineage",
            "projection differs from exact seed plan IR request candidate receipt or unresolved lineage",
        );
    }
    exact_non_authority(&projection.non_authority, "projection.non_authority")?;
    validate_compilation_outcome(request, &projection.compilation)?;
    validate_digest(
        &projection.projection_digest,
        "projection.projection_digest",
    )?;
    require_digest(
        &projection.projection_digest,
        attention_procedure_backend_projection_digest(projection)?,
        "projection.projection_digest",
    )
}

fn validate_attention_backend_request(
    seed: &SopSeed,
    ir: &TypedSopIr,
    plan: &CandidateCompilationPlan,
    request: &AttentionProcedureBackendRequest,
) -> SemanticCompilerValidation {
    validate_candidate_compilation_plan(seed, ir, plan)?;
    exact_profile(
        &request.profile,
        ATTENTION_PROCEDURE_BACKEND_REQUEST_PROFILE,
        "request.profile",
    )?;
    if plan.backend != CompilerBackendKind::AttentionProcedure {
        return form_fault(
            SemanticCompilerFormFaultKind::BackendMismatch,
            "plan.backend",
            "attention procedure adapter requires the exact attention_procedure backend",
        );
    }
    if request.plan_ref != plan.plan_id
        || request.plan_digest != plan.plan_digest
        || request.ir_ref != ir.ir_id
        || request.ir_digest != ir.ir_digest
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "request.lineage",
            "request plan or IR lineage differs from validated inputs",
        );
    }
    let pure_capabilities = BTreeSet::from([
        CompilerCapability::SemanticRead,
        CompilerCapability::SourceRead,
    ]);
    if !plan.requested_capabilities.is_subset(&pure_capabilities) {
        return form_fault(
            SemanticCompilerFormFaultKind::CapabilityExceeded,
            "plan.requested_capabilities",
            "attention procedure projection permits semantic_read and source_read only",
        );
    }
    let candidate = &request.candidate;
    if normalize(&candidate.purpose) != normalize(&plan.purpose)
        || !candidate.provenance_refs.contains(&plan.plan_id)
        || !candidate.provenance_refs.contains(&ir.ir_id)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "request.candidate.contract",
            "candidate purpose or plan and IR provenance differs",
        );
    }
    if candidate.language_profile != CPPE_FORM_VERSION
        || candidate.source_text.is_some()
        || candidate.normalized_source_form.is_none()
        || candidate.lifecycle != ProcedureLifecycle::Proposed
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidProfile,
            "request.candidate.machine_form",
            "candidate must be a proposed normalized CPPE machine form without text source",
        );
    }
    let source_digest = compute_candidate_source_digest(candidate)
        .map_err(|error| compiler_fault("request.candidate.source_digest", error.to_string()))?;
    if candidate.source_digest != source_digest {
        return form_fault(
            SemanticCompilerFormFaultKind::DigestMismatch,
            "request.candidate.source_digest",
            "candidate source digest differs from normalized source form",
        );
    }
    let mut forms = ProcedureFormSet::new();
    forms
        .candidates
        .insert(candidate.candidate_id.clone(), candidate.clone());
    validate_procedure_forms(&forms)
        .map_err(|error| compiler_fault("request.candidate", error.to_string()))?;

    validate_validation_receipt(plan, ir, candidate, &request.validation_receipt)?;
    validate_anchor_correspondence(ir, candidate, &request.semantic_node_anchor_map)?;
    bounded_set(&request.unresolved_account, "request.unresolved_account")?;
    exact_non_authority(&request.non_authority, "request.non_authority")
}

fn validate_validation_receipt(
    plan: &CandidateCompilationPlan,
    ir: &TypedSopIr,
    candidate: &ProcedureCandidate,
    receipt: &ValidationReceipt,
) -> SemanticCompilerValidation {
    if receipt.candidate_ref != candidate.candidate_id
        || receipt.candidate_source_digest != candidate.source_digest
        || receipt.profile != CPPE_FORM_VERSION
        || receipt.disposition != PhaseDisposition::Passed
        || !plan.verifier_refs.contains(&receipt.validator_ref)
        || !receipt.evidence.evidence_refs.contains(&plan.plan_id)
        || !receipt.evidence.evidence_refs.contains(&ir.ir_id)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "request.validation_receipt",
            "receipt must pass for the exact candidate under a named plan verifier with plan and IR evidence",
        );
    }
    let expected = compute_validation_receipt_digest(receipt)
        .map_err(|error| compiler_fault("request.validation_receipt", error.to_string()))?;
    if receipt.receipt_digest != expected {
        return form_fault(
            SemanticCompilerFormFaultKind::DigestMismatch,
            "request.validation_receipt.receipt_digest",
            "validation receipt digest differs from canonical form",
        );
    }
    Ok(())
}

fn validate_anchor_correspondence(
    ir: &TypedSopIr,
    candidate: &ProcedureCandidate,
    node_anchor_map: &BTreeMap<SemanticId, SemanticId>,
) -> SemanticCompilerValidation {
    if node_anchor_map.keys().collect::<BTreeSet<_>>() != ir.nodes.keys().collect::<BTreeSet<_>>() {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "request.semantic_node_anchor_map",
            "every semantic IR node must have exactly one mapping",
        );
    }
    let mapped_anchors = node_anchor_map.values().cloned().collect::<BTreeSet<_>>();
    if mapped_anchors.len() != node_anchor_map.len()
        || mapped_anchors
            != candidate
                .sop_anchors
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
    {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "request.semantic_node_anchor_map",
            "mapped anchors must be distinct and equal the complete candidate SOP anchor set",
        );
    }
    for (node_id, anchor_id) in node_anchor_map {
        let node = &ir.nodes[node_id];
        let binding = &candidate.sop_anchors[anchor_id];
        let address = &node.semantic_address;
        let clause_matches = binding.clause_id.as_ref().is_some_and(|clause_id| {
            address
                .source_anchors
                .iter()
                .any(|anchor| &anchor.clause_id == clause_id)
        });
        if binding.anchor_id != *anchor_id
            || binding.artifact_id != address.package_id
            || binding.artifact_version != address.version
            || binding.artifact_digest != address.package_digest
            || !clause_matches
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "request.semantic_node_anchor_map",
                "procedure anchor does not name the node's exact package version digest and source clause",
            );
        }
    }
    Ok(())
}

fn validate_compilation_outcome(
    request: &AttentionProcedureBackendRequest,
    outcome: &CompilationOutcome,
) -> SemanticCompilerValidation {
    let receipt = &outcome.compilation_receipt;
    if receipt.candidate_ref != request.candidate.candidate_id
        || receipt.candidate_source_digest != request.candidate.source_digest
        || receipt.validation_receipt_ref != request.validation_receipt.receipt_id
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "projection.compilation.lineage",
            "compilation receipt differs from candidate or validation receipt lineage",
        );
    }
    let expected = compute_compilation_receipt_digest(receipt)
        .map_err(|error| compiler_fault("projection.compilation.receipt", error.to_string()))?;
    if receipt.receipt_digest != expected {
        return form_fault(
            SemanticCompilerFormFaultKind::DigestMismatch,
            "projection.compilation.receipt_digest",
            "compilation receipt digest differs from canonical form",
        );
    }
    let has_artifacts = outcome.process_ir.is_some() && outcome.compiled_procedure.is_some();
    let has_none = outcome.process_ir.is_none() && outcome.compiled_procedure.is_none();
    if !matches!(
        (&receipt.disposition, has_artifacts, has_none),
        (PhaseDisposition::Passed, true, false)
            | (
                PhaseDisposition::Refused | PhaseDisposition::Faulted,
                false,
                true
            )
    ) {
        return form_fault(
            SemanticCompilerFormFaultKind::AccountingMismatch,
            "projection.compilation.disposition",
            "passed compilation requires both artifacts and refused or faulted compilation requires neither",
        );
    }
    let mut forms = ProcedureFormSet::new();
    forms.candidates.insert(
        request.candidate.candidate_id.clone(),
        request.candidate.clone(),
    );
    forms.validation_receipts.insert(
        request.validation_receipt.receipt_id.clone(),
        request.validation_receipt.clone(),
    );
    forms
        .compilation_receipts
        .insert(receipt.receipt_id.clone(), receipt.clone());
    if let Some(ir) = &outcome.process_ir {
        forms.process_irs.insert(ir.ir_id.clone(), ir.clone());
    }
    if let Some(procedure) = &outcome.compiled_procedure {
        forms
            .compiled_procedures
            .insert(procedure.procedure_id.clone(), procedure.clone());
    }
    validate_procedure_forms(&forms)
        .map_err(|error| compiler_fault("projection.compilation", error.to_string()))?;
    Ok(())
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn compiler_fault(field: &str, detail: String) -> SemanticCompilerFormFault {
    SemanticCompilerFormFault {
        kind: SemanticCompilerFormFaultKind::InvalidReference,
        field: field.to_owned(),
        detail,
    }
}
