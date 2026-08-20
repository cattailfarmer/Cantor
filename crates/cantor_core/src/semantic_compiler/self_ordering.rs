use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::*;
use crate::{
    DerivedLexicalAssociationIndex, DerivedSemanticAnchorCatalogue, LexicalAnchorLookupRequest,
    LexicalAnchorLookupResult, LexicalAnchorMatch, LexicalAnchorSourceProjectionBudget,
    LexicalAnchorSourceProjectionResult, SemanticFabric, VerifiedAnchorSourceProjection,
    validate_lexical_anchor_lookup_result, validate_lexical_anchor_source_projection_result,
};

pub const SELF_ORDERING_REQUEST_PROFILE: &str = "cantor-self-ordering-request/0.1";
pub const PROVIDER_FREE_SELF_ORDERING_PROJECTION_PROFILE: &str =
    "cantor-provider-free-self-ordering-projection/0.1";

const SELF_ORDERING_IR_ID_DOMAIN: &str = "cantor.semantic-compiler.self-ordering.ir-id.v1";
const SELF_ORDERING_PLAN_ID_DOMAIN: &str = "cantor.semantic-compiler.self-ordering.plan-id.v1";
const SELF_ORDERING_LEDGER_ID_DOMAIN: &str = "cantor.semantic-compiler.self-ordering.ledger-id.v1";
const SELF_ORDERING_DESCRIPTION_ENTRY_DOMAIN: &str =
    "cantor.semantic-compiler.self-ordering.description-entry.v1";
const SELF_ORDERING_PLAN_ENTRY_DOMAIN: &str =
    "cantor.semantic-compiler.self-ordering.plan-entry.v1";
const SELF_ORDERING_PROJECTION_DOMAIN: &str =
    "cantor.semantic-compiler.self-ordering.projection.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfOrderingNodeDirective {
    pub source_unit_ref: SemanticId,
    pub node_id: SemanticId,
    pub kind: SemanticIrNodeKind,
    pub type_ref: Option<SemanticId>,
    pub dependency_refs: BTreeSet<SemanticId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfOrderingRequest {
    pub profile: String,
    pub request_id: SemanticId,
    pub source_manifest_ref: SemanticId,
    pub canonical_specification_ref: SemanticId,
    pub purpose: String,
    pub backend: CompilerBackendKind,
    pub requested_capabilities: BTreeSet<CompilerCapability>,
    pub node_directives: Vec<SelfOrderingNodeDirective>,
    pub verifier_refs: BTreeSet<SemanticId>,
    pub rollback_ref: SemanticId,
    pub unresolved_account: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFreeSelfOrderingProjection {
    pub profile: String,
    pub request_id: SemanticId,
    pub seed_ref: SemanticId,
    pub seed_digest: ContentDigest,
    pub lookup_proof_digest: ContentDigest,
    pub source_projection_proof_digest: ContentDigest,
    pub ir: TypedSopIr,
    pub plan: CandidateCompilationPlan,
    pub ledger: SelfAssemblyLedger,
    pub non_authority: String,
    pub projection_digest: ContentDigest,
}

pub fn provider_free_self_ordering_projection_digest(
    projection: &ProviderFreeSelfOrderingProjection,
) -> SemanticCompilerValidation<ContentDigest> {
    digest_form(
        SELF_ORDERING_PROJECTION_DOMAIN,
        &(
            &projection.profile,
            &projection.request_id,
            &projection.seed_ref,
            &projection.seed_digest,
            &projection.lookup_proof_digest,
            &projection.source_projection_proof_digest,
            &projection.ir,
            &projection.plan,
            &projection.ledger,
            &projection.non_authority,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn project_provider_free_self_ordering(
    seed: &SopSeed,
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    index: &DerivedLexicalAssociationIndex,
    lookup_request: &LexicalAnchorLookupRequest,
    lookup_result: &LexicalAnchorLookupResult,
    source_projection_budget: &LexicalAnchorSourceProjectionBudget,
    source_projection: &LexicalAnchorSourceProjectionResult,
    request: SelfOrderingRequest,
) -> SemanticCompilerValidation<ProviderFreeSelfOrderingProjection> {
    validate_projection_inputs(
        seed,
        fabric,
        catalogue,
        index,
        lookup_request,
        lookup_result,
        source_projection_budget,
        source_projection,
        &request,
    )?;
    let projection = build_projection(
        seed,
        catalogue,
        lookup_request,
        lookup_result,
        source_projection,
        &request,
    )?;
    validate_projection_shape(seed, lookup_result, source_projection, &projection)?;
    Ok(projection)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_provider_free_self_ordering_projection(
    seed: &SopSeed,
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    index: &DerivedLexicalAssociationIndex,
    lookup_request: &LexicalAnchorLookupRequest,
    lookup_result: &LexicalAnchorLookupResult,
    source_projection_budget: &LexicalAnchorSourceProjectionBudget,
    source_projection: &LexicalAnchorSourceProjectionResult,
    request: &SelfOrderingRequest,
    projection: &ProviderFreeSelfOrderingProjection,
) -> SemanticCompilerValidation {
    validate_projection_inputs(
        seed,
        fabric,
        catalogue,
        index,
        lookup_request,
        lookup_result,
        source_projection_budget,
        source_projection,
        request,
    )?;
    validate_projection_shape(seed, lookup_result, source_projection, projection)?;
    let expected = build_projection(
        seed,
        catalogue,
        lookup_request,
        lookup_result,
        source_projection,
        request,
    )?;
    if projection != &expected {
        return form_fault(
            SemanticCompilerFormFaultKind::DigestMismatch,
            "self_ordering_projection",
            "projection differs from canonical provider-free replay",
        );
    }
    Ok(())
}

pub fn validate_self_ordering_request(
    seed: &SopSeed,
    request: &SelfOrderingRequest,
) -> SemanticCompilerValidation {
    validate_sop_seed(seed)?;
    exact_profile(
        &request.profile,
        SELF_ORDERING_REQUEST_PROFILE,
        "self_ordering_request.profile",
    )?;
    bounded_text(&request.purpose, "self_ordering_request.purpose")?;
    bounded_set(
        &request.unresolved_account,
        "self_ordering_request.unresolved_account",
    )?;
    if normalize(&request.purpose) != normalize(&seed.purpose) {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "self_ordering_request.purpose",
            "request purpose differs from the exact seed purpose",
        );
    }
    if request.source_manifest_ref == request.canonical_specification_ref
        || !seed
            .dependency_roots
            .contains_key(&request.source_manifest_ref)
        || !seed
            .dependency_roots
            .contains_key(&request.canonical_specification_ref)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "self_ordering_request.dependencies",
            "source manifest and canonical specification must be distinct exact seed dependencies",
        );
    }
    if !seed.backend_profiles.contains_key(&request.backend) {
        return form_fault(
            SemanticCompilerFormFaultKind::BackendMismatch,
            "self_ordering_request.backend",
            "backend is not registered by the exact seed",
        );
    }
    if !request
        .requested_capabilities
        .is_subset(&seed.capability_ceiling.capabilities)
    {
        return form_fault(
            SemanticCompilerFormFaultKind::CapabilityExceeded,
            "self_ordering_request.requested_capabilities",
            "requested capability exceeds the seed ceiling",
        );
    }
    if request.node_directives.is_empty()
        || request.node_directives.len() > MAX_COLLECTION_ITEMS
        || request.verifier_refs.is_empty()
        || request.verifier_refs.len() > MAX_COLLECTION_ITEMS
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidBound,
            "self_ordering_request",
            "node directives and verifier references must be nonempty and bounded",
        );
    }
    let mut prior_node: Option<&SemanticId> = None;
    let mut source_units = BTreeSet::new();
    for directive in &request.node_directives {
        if prior_node.is_some_and(|prior| prior >= &directive.node_id)
            || !source_units.insert(&directive.source_unit_ref)
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "self_ordering_request.node_directives",
                "node directives must be strictly node-id ordered with unique source units",
            );
        }
        prior_node = Some(&directive.node_id);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_projection_inputs(
    seed: &SopSeed,
    fabric: &SemanticFabric,
    catalogue: &DerivedSemanticAnchorCatalogue,
    index: &DerivedLexicalAssociationIndex,
    lookup_request: &LexicalAnchorLookupRequest,
    lookup_result: &LexicalAnchorLookupResult,
    source_projection_budget: &LexicalAnchorSourceProjectionBudget,
    source_projection: &LexicalAnchorSourceProjectionResult,
    request: &SelfOrderingRequest,
) -> SemanticCompilerValidation {
    validate_self_ordering_request(seed, request)?;
    for package in &catalogue.generation.packages {
        if seed.dependency_roots.get(&package.package_id) != Some(&package.package_digest) {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "seed.dependency_roots",
                "seed does not bind every admitted package identity and digest",
            );
        }
    }
    validate_lexical_anchor_lookup_result(lookup_result, lookup_request, index, catalogue, fabric)
        .map_err(|fault| SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::InvalidReference,
            field: format!("lookup.{}", fault.field),
            detail: fault.detail,
        })?;
    validate_lexical_anchor_source_projection_result(
        source_projection,
        fabric,
        catalogue,
        index,
        lookup_request,
        lookup_result,
        source_projection_budget,
    )
    .map_err(|fault| SemanticCompilerFormFault {
        kind: SemanticCompilerFormFaultKind::InvalidReference,
        field: format!("source_projection.{}", fault.field),
        detail: fault.detail,
    })
}

fn build_projection(
    seed: &SopSeed,
    catalogue: &DerivedSemanticAnchorCatalogue,
    lookup_request: &LexicalAnchorLookupRequest,
    lookup_result: &LexicalAnchorLookupResult,
    source_projection: &LexicalAnchorSourceProjectionResult,
    request: &SelfOrderingRequest,
) -> SemanticCompilerValidation<ProviderFreeSelfOrderingProjection> {
    let matches = unique_matches(lookup_result)?;
    let projections = unique_projections(source_projection)?;
    let mut nodes = BTreeMap::new();
    let mut source_map = BTreeMap::new();
    let mut selected_units = BTreeSet::new();
    for directive in &request.node_directives {
        let matched =
            matches
                .get(&directive.source_unit_ref)
                .ok_or_else(|| SemanticCompilerFormFault {
                    kind: SemanticCompilerFormFaultKind::InvalidReference,
                    field: "self_ordering_request.node_directives.source_unit_ref".to_owned(),
                    detail: "selected unit is absent from the validated lookup".to_owned(),
                })?;
        let projected = projections.get(&directive.source_unit_ref).ok_or_else(|| {
            SemanticCompilerFormFault {
                kind: SemanticCompilerFormFaultKind::InvalidReference,
                field: "self_ordering_request.node_directives.source_unit_ref".to_owned(),
                detail: "selected unit lacks an exact validated source projection".to_owned(),
            }
        })?;
        if matched.address != projected.address {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "self_ordering_request.node_directives.source_unit_ref",
                "lookup and source-projection addresses differ",
            );
        }
        selected_units.insert(directive.source_unit_ref.clone());
        let mut derivation_refs = BTreeSet::from([projected.certificate_id.clone()]);
        for evidence in &matched.evidence {
            derivation_refs.extend(evidence.evidence_refs.iter().cloned());
        }
        let node = SemanticIrNode {
            node_id: directive.node_id.clone(),
            kind: directive.kind.clone(),
            semantic_address: matched.address.clone(),
            type_ref: directive.type_ref.clone(),
            dependency_refs: directive.dependency_refs.clone(),
            generated_derivation_refs: derivation_refs.clone(),
        };
        nodes.insert(directive.node_id.clone(), node);
        source_map.insert(
            directive.node_id.clone(),
            CompilerSourceMapEntry {
                node_ref: directive.node_id.clone(),
                semantic_address: matched.address.clone(),
                derivation_refs,
            },
        );
    }

    let mut unresolved_account = request.unresolved_account.clone();
    unresolved_account.extend(
        lookup_result
            .unmatched_tokens
            .iter()
            .map(|token| format!("unmatched lexical token: {token}")),
    );
    unresolved_account.extend(
        matches
            .keys()
            .filter(|unit| !selected_units.contains(*unit))
            .map(|unit| format!("unselected admitted match: {unit}")),
    );
    unresolved_account.extend(
        catalogue
            .omissions
            .iter()
            .filter(|omission| selected_units.contains(&omission.unit_id))
            .map(|omission| {
                format!(
                    "catalogue omission {}: {}",
                    omission.unit_id, omission.reason
                )
            }),
    );

    let ir_identity = digest_form(
        SELF_ORDERING_IR_ID_DOMAIN,
        &(
            &seed.seed_digest,
            &lookup_result.proof_digest,
            &source_projection.proof_digest,
            request,
        ),
    )?;
    let mut ir = TypedSopIr {
        profile: TYPED_SOP_IR_PROFILE.to_owned(),
        ir_id: derived_id("ir:self-ordering", &ir_identity)?,
        source_manifest_digest: seed.dependency_roots[&request.source_manifest_ref].clone(),
        canonical_specification_ref: request.canonical_specification_ref.clone(),
        canonical_specification_digest: seed.dependency_roots[&request.canonical_specification_ref]
            .clone(),
        nodes,
        source_map,
        unresolved_account,
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        ir_digest: zero_digest(),
    };
    ir.ir_digest = typed_sop_ir_digest(&ir)?;
    validate_typed_sop_ir(&ir)?;

    let input_refs = ir
        .nodes
        .iter()
        .filter(|(_, node)| node.kind == SemanticIrNodeKind::Input)
        .map(|(node_id, _)| node_id.clone())
        .collect();
    let expected_output_refs = ir
        .nodes
        .iter()
        .filter(|(_, node)| node.kind == SemanticIrNodeKind::Output)
        .map(|(node_id, _)| node_id.clone())
        .collect();
    let plan_identity = digest_form(
        SELF_ORDERING_PLAN_ID_DOMAIN,
        &(&seed.seed_digest, &ir.ir_digest, request),
    )?;
    let mut plan = CandidateCompilationPlan {
        profile: CANDIDATE_COMPILATION_PLAN_PROFILE.to_owned(),
        plan_id: derived_id("plan:self-ordering", &plan_identity)?,
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        ir_ref: ir.ir_id.clone(),
        ir_digest: ir.ir_digest.clone(),
        backend: request.backend.clone(),
        backend_profile: seed.backend_profiles[&request.backend].clone(),
        purpose: request.purpose.clone(),
        requested_capabilities: request.requested_capabilities.clone(),
        input_refs,
        expected_output_refs,
        verifier_refs: request.verifier_refs.clone(),
        rollback_ref: request.rollback_ref.clone(),
        unresolved_account: ir.unresolved_account.clone(),
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        plan_digest: zero_digest(),
    };
    plan.plan_digest = candidate_compilation_plan_digest(&plan)?;
    validate_candidate_compilation_plan(seed, &ir, &plan)?;

    let description_evidence = source_projection
        .projections
        .iter()
        .filter(|projection| selected_units.contains(&projection.address.unit_id))
        .map(|projection| projection.certificate_id.clone())
        .chain(std::iter::once(lookup_request.request_id.clone()))
        .collect();
    let ledger_identity = digest_form(
        SELF_ORDERING_LEDGER_ID_DOMAIN,
        &(&seed.seed_digest, &ir.ir_digest, &plan.plan_digest),
    )?;
    let mut ledger = SelfAssemblyLedger {
        profile: SELF_ASSEMBLY_LEDGER_PROFILE.to_owned(),
        ledger_id: derived_id("ledger:self-ordering", &ledger_identity)?,
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        predecessor_generation_ref: seed.generation_id.clone(),
        successor_generation_ref: None,
        rollback_ref: request.rollback_ref.clone(),
        entries: vec![
            SelfAssemblyEntry {
                entry_id: derived_id(
                    "entry:self-description",
                    &digest_form(
                        SELF_ORDERING_DESCRIPTION_ENTRY_DOMAIN,
                        &(&ir.ir_digest, &lookup_result.proof_digest),
                    )?,
                )?,
                stage: SelfAssemblyStage::SelfDescription,
                plan_ref: None,
                candidate_artifact_ref: None,
                honesty_receipt_ref: None,
                security_receipt_ref: None,
                external_recognition_ref: None,
                evidence_refs: description_evidence,
                disposition: SelfAssemblyDisposition::Observed,
            },
            SelfAssemblyEntry {
                entry_id: derived_id(
                    "entry:self-ordering",
                    &digest_form(
                        SELF_ORDERING_PLAN_ENTRY_DOMAIN,
                        &(&ir.ir_digest, &plan.plan_digest),
                    )?,
                )?,
                stage: SelfAssemblyStage::SelfOrdering,
                plan_ref: Some(plan.plan_id.clone()),
                candidate_artifact_ref: None,
                honesty_receipt_ref: None,
                security_receipt_ref: None,
                external_recognition_ref: None,
                evidence_refs: request.verifier_refs.clone(),
                disposition: SelfAssemblyDisposition::Candidate,
            },
        ],
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        ledger_digest: zero_digest(),
    };
    ledger.ledger_digest = self_assembly_ledger_digest(&ledger)?;
    validate_self_assembly_ledger(seed, &ledger)?;

    let mut result = ProviderFreeSelfOrderingProjection {
        profile: PROVIDER_FREE_SELF_ORDERING_PROJECTION_PROFILE.to_owned(),
        request_id: request.request_id.clone(),
        seed_ref: seed.seed_id.clone(),
        seed_digest: seed.seed_digest.clone(),
        lookup_proof_digest: lookup_result.proof_digest.clone(),
        source_projection_proof_digest: source_projection.proof_digest.clone(),
        ir,
        plan,
        ledger,
        non_authority: COMPILER_NON_AUTHORITY.to_owned(),
        projection_digest: zero_digest(),
    };
    result.projection_digest = provider_free_self_ordering_projection_digest(&result)?;
    Ok(result)
}

fn validate_projection_shape(
    seed: &SopSeed,
    lookup_result: &LexicalAnchorLookupResult,
    source_projection: &LexicalAnchorSourceProjectionResult,
    projection: &ProviderFreeSelfOrderingProjection,
) -> SemanticCompilerValidation {
    exact_profile(
        &projection.profile,
        PROVIDER_FREE_SELF_ORDERING_PROJECTION_PROFILE,
        "self_ordering_projection.profile",
    )?;
    if projection.seed_ref != seed.seed_id
        || projection.seed_digest != seed.seed_digest
        || projection.lookup_proof_digest != lookup_result.proof_digest
        || projection.source_projection_proof_digest != source_projection.proof_digest
    {
        return form_fault(
            SemanticCompilerFormFaultKind::InvalidReference,
            "self_ordering_projection.lineage",
            "projection seed lookup or source proof lineage differs",
        );
    }
    exact_non_authority(
        &projection.non_authority,
        "self_ordering_projection.non_authority",
    )?;
    validate_typed_sop_ir(&projection.ir)?;
    validate_candidate_compilation_plan(seed, &projection.ir, &projection.plan)?;
    validate_self_assembly_ledger(seed, &projection.ledger)?;
    if projection.ledger.entries.len() != 2
        || projection.ledger.entries[0].stage != SelfAssemblyStage::SelfDescription
        || projection.ledger.entries[0].disposition != SelfAssemblyDisposition::Observed
        || projection.ledger.entries[1].stage != SelfAssemblyStage::SelfOrdering
        || projection.ledger.entries[1].disposition != SelfAssemblyDisposition::Candidate
        || projection.ledger.successor_generation_ref.is_some()
        || projection.ledger.entries.iter().any(|entry| {
            entry.candidate_artifact_ref.is_some()
                || entry.honesty_receipt_ref.is_some()
                || entry.security_receipt_ref.is_some()
                || entry.external_recognition_ref.is_some()
        })
    {
        return form_fault(
            SemanticCompilerFormFaultKind::RecognitionBoundary,
            "self_ordering_projection.ledger",
            "Slice2 projection must stop at observed self-description and candidate self-ordering",
        );
    }
    validate_digest(
        &projection.projection_digest,
        "self_ordering_projection.projection_digest",
    )?;
    require_digest(
        &projection.projection_digest,
        provider_free_self_ordering_projection_digest(projection)?,
        "self_ordering_projection.projection_digest",
    )
}

fn unique_matches(
    result: &LexicalAnchorLookupResult,
) -> SemanticCompilerValidation<BTreeMap<SemanticId, &LexicalAnchorMatch>> {
    let mut matches = BTreeMap::new();
    for matched in &result.matches {
        if matches
            .insert(matched.address.unit_id.clone(), matched)
            .is_some()
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "lookup.matches",
                "lookup contains duplicate unit identities",
            );
        }
    }
    Ok(matches)
}

fn unique_projections(
    result: &LexicalAnchorSourceProjectionResult,
) -> SemanticCompilerValidation<BTreeMap<SemanticId, &VerifiedAnchorSourceProjection>> {
    let mut projections = BTreeMap::new();
    for projection in &result.projections {
        if projections
            .insert(projection.address.unit_id.clone(), projection)
            .is_some()
        {
            return form_fault(
                SemanticCompilerFormFaultKind::InvalidReference,
                "source_projection.projections",
                "source projection contains duplicate unit identities",
            );
        }
    }
    Ok(projections)
}

fn derived_id(prefix: &str, digest: &ContentDigest) -> SemanticCompilerValidation<SemanticId> {
    SemanticId::new(format!("{prefix}:{}", digest.value)).map_err(|error| {
        SemanticCompilerFormFault {
            kind: SemanticCompilerFormFaultKind::InvalidReference,
            field: "derived_identity".to_owned(),
            detail: error.to_string(),
        }
    })
}

fn zero_digest() -> ContentDigest {
    ContentDigest {
        algorithm: DIGEST_ALGORITHM.to_owned(),
        value: "0".repeat(64),
    }
}
