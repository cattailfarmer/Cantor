//! Deterministic exact scanning over a proof-bound semantic anchor catalogue.
//!
//! Slice 3 consumes a catalogue derived from one already admitted
//! `SemanticFabric`. It supports exact identity, exact label, declared
//! applicability, and bounded typed-relation proposals only. It performs no
//! lexical, embedding, learned, provider, persistence, remote, or effect work.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    ANCHOR_QUERY_RESULT_PROFILE, AnchorCandidate, AnchorLifecycle, AnchorProof, AnchorQuery,
    AnchorQueryResult, ApplicabilityStatus, AssociationChannel, AssociationContribution,
    BoundaryAccount, CandidateEligibility, ChannelLocalValue, ContentDigest, ContributionStatus,
    DerivedSemanticAnchorCatalogue, IdentityAnchorEntry, PriorityTier, SemanticAddress,
    SemanticFabric, SemanticId, SemanticRelation, SourceAnchor, UnitStatus,
    anchor_query_result_digest, validate_anchor_query, validate_anchor_query_result,
    validate_derived_semantic_anchor_catalogue,
};

pub const EXACT_ANCHOR_SCAN_PROFILE: &str = "cantor-exact-anchor-scan/0.1";

const DIGEST_ALGORITHM: &str = "sha256";
const INPUT_DOMAIN: &str = "cantor.semantic-anchor-scan.input.v1";
const CURSOR_DOMAIN: &str = "cantor.semantic-anchor-scan.cursor.v1";
const MAX_CURSOR_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnchorScanFaultKind {
    InvalidQuery,
    UnsupportedChannel,
    CatalogueMismatch,
    InvalidContinuation,
    AddressUnresolved,
    BudgetTooSmall,
    ResultMismatch,
    Serialization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorScanFault {
    pub kind: AnchorScanFaultKind,
    pub stage: String,
    pub detail: String,
    pub related_ids: Vec<SemanticId>,
}

pub type AnchorScanResult<T = AnchorQueryResult> = Result<T, AnchorScanFault>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    profile: String,
    catalogue_root: ContentDigest,
    fabric_root: ContentDigest,
    input_digest: ContentDigest,
    offset: u32,
    ordinal: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorEnvelope {
    payload: CursorPayload,
    commitment: ContentDigest,
}

#[derive(Clone, Debug)]
struct CandidateAccumulator {
    address: SemanticAddress,
    contributions: Vec<AssociationContribution>,
    eligibility: CandidateEligibility,
    unresolved_guards: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct GateOutcome {
    eligibility: CandidateEligibility,
    unresolved_guards: BTreeSet<String>,
    decisions: Vec<String>,
    omissions: Vec<String>,
}

#[derive(Clone, Debug)]
struct TraversalState {
    node: SemanticId,
    nodes: Vec<SemanticId>,
    relations: Vec<SemanticId>,
}

/// Deterministically scans the exact proposal channels admitted by Slice 3.
pub fn scan_exact_semantic_anchors(
    derived: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
    query: &AnchorQuery,
    continuation: Option<&str>,
) -> AnchorScanResult {
    validate_anchor_query(query).map_err(|fault| AnchorScanFault {
        kind: AnchorScanFaultKind::InvalidQuery,
        stage: fault.field,
        detail: fault.detail,
        related_ids: vec![query.request_id.clone()],
    })?;
    validate_derived_semantic_anchor_catalogue(derived, fabric).map_err(|fault| {
        AnchorScanFault {
            kind: AnchorScanFaultKind::CatalogueMismatch,
            stage: fault.stage,
            detail: fault.detail,
            related_ids: fault.related_ids,
        }
    })?;
    validate_slice3_channels(query)?;
    validate_scan_collection_bounds(query)?;
    if query.authority_context.effect_boundary != "read_only"
        || query.authority_context.operation.trim().is_empty()
    {
        return scan_fault(
            AnchorScanFaultKind::InvalidQuery,
            "authority_context",
            "exact scanning requires a nonempty operation and read_only effect boundary",
            vec![query.authority_context.caller_id.clone()],
        );
    }

    let input_digest = exact_anchor_scan_input_digest(query)?;
    let cursor = continuation.map(decode_cursor).transpose()?;
    let (offset, ordinal) = validate_cursor(derived, &input_digest, query, cursor.as_ref())?;

    let entries = derived
        .catalogue
        .identity_entries
        .iter()
        .map(|entry| (entry.address.unit_id.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut accumulators = BTreeMap::<SemanticId, CandidateAccumulator>::new();
    let mut unknown = BTreeSet::<String>::new();
    let mut decisions = Vec::<String>::new();
    let mut omissions = Vec::<String>::new();
    let scan_capacity = scan_candidate_capacity(query);
    if query.known_identities.len() > scan_capacity {
        return scan_fault(
            AnchorScanFaultKind::InvalidQuery,
            "known_identities",
            "known identities exceed the candidate capacity represented by pages and continuations",
            vec![query.request_id.clone()],
        );
    }

    gather_exact_identity(
        derived,
        query,
        &entries,
        &mut accumulators,
        &mut unknown,
        scan_capacity,
    );
    let mut discovery_clipped = gather_exact_labels(
        derived,
        query,
        &entries,
        &mut accumulators,
        &mut unknown,
        scan_capacity,
    );

    for accumulator in accumulators.values_mut() {
        let entry = entries
            .get(&accumulator.address.unit_id)
            .copied()
            .ok_or_else(|| unresolved_fault(&accumulator.address.unit_id, "seed_entry"))?;
        let outcome = gate_identity(entry, derived, fabric, query)?;
        apply_gate(accumulator, &outcome);
        decisions.extend(outcome.decisions);
        omissions.extend(outcome.omissions);
    }

    if query
        .allowed_channels
        .contains(&AssociationChannel::DeclaredApplicability)
    {
        discovery_clipped |= gather_declared_applicability(
            derived,
            fabric,
            query,
            &entries,
            &mut accumulators,
            &mut decisions,
            &mut omissions,
            scan_capacity,
        )?;
    }

    let path_clipped = if query
        .allowed_channels
        .contains(&AssociationChannel::TypedRelation)
    {
        gather_typed_relations(
            derived,
            fabric,
            query,
            &entries,
            &mut accumulators,
            &mut decisions,
            &mut omissions,
            scan_capacity,
        )?
    } else {
        false
    };

    if !query.requested_details.is_empty() {
        omissions.push(
            "compact requested-detail projection is deferred to Semantic Anchor Catalogue Slice4"
                .to_owned(),
        );
    }
    if query.subject.is_some() {
        omissions.push(
            "free-form subject is proof-bound input but is not converted into similarity or an inferred context gate"
                .to_owned(),
        );
    }
    omissions.push(
        "elapsed-millisecond budget validated without consulting a nondeterministic wall clock"
            .to_owned(),
    );
    for omission in &derived.omissions {
        omissions.push(format!(
            "derived omission {}: {} [{}]",
            omission.unit_id,
            omission.reason,
            omission
                .omitted_fields
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        ));
    }

    decisions.sort();
    decisions.dedup();
    omissions.sort();
    omissions.dedup();
    let mut candidates = finalize_candidates(accumulators)?;
    apply_winning_ambiguity(&mut candidates, &mut decisions);
    candidates.sort_by(candidate_order);

    build_bounded_result(
        derived,
        query,
        input_digest,
        candidates,
        unknown.into_iter().collect(),
        decisions,
        omissions,
        offset,
        ordinal,
        path_clipped || discovery_clipped,
    )
}

/// Re-runs the pure scanner and requires whole-result equality.
pub fn validate_exact_anchor_scan_result(
    derived: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
    query: &AnchorQuery,
    continuation: Option<&str>,
    result: &AnchorQueryResult,
) -> AnchorScanResult<()> {
    validate_anchor_query_result(result).map_err(|fault| AnchorScanFault {
        kind: AnchorScanFaultKind::ResultMismatch,
        stage: fault.field,
        detail: fault.detail,
        related_ids: vec![query.request_id.clone()],
    })?;
    let expected = scan_exact_semantic_anchors(derived, fabric, query, continuation)?;
    if &expected != result {
        return scan_fault(
            AnchorScanFaultKind::ResultMismatch,
            "result",
            "result differs from a canonical exact scanner rebuild",
            vec![query.request_id.clone()],
        );
    }
    Ok(())
}

pub fn exact_anchor_scan_input_digest(query: &AnchorQuery) -> AnchorScanResult<ContentDigest> {
    digest_form(INPUT_DOMAIN, query)
}

fn validate_slice3_channels(query: &AnchorQuery) -> AnchorScanResult<()> {
    let allowed = BTreeSet::from([
        AssociationChannel::ExactIdentity,
        AssociationChannel::ExactLabel,
        AssociationChannel::DeclaredApplicability,
        AssociationChannel::TypedRelation,
    ]);
    let unsupported = query
        .allowed_channels
        .difference(&allowed)
        .cloned()
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        Ok(())
    } else {
        scan_fault(
            AnchorScanFaultKind::UnsupportedChannel,
            "allowed_channels",
            &format!("Slice3 does not admit channels {unsupported:?}"),
            vec![query.request_id.clone()],
        )
    }
}

fn validate_scan_collection_bounds(query: &AnchorQuery) -> AnchorScanResult<()> {
    if query.term_set.len() > 1024
        || query.known_identities.len() > 1024
        || query.use_cases.len() > 256
        || query.include_boundaries.len() > 256
        || query.exclude_boundaries.len() > 256
        || query.requested_details.len() > 64
        || query.allowed_relations.len() > 64
        || query.allowed_channels.len() > 7
    {
        return scan_fault(
            AnchorScanFaultKind::InvalidQuery,
            "query.collections",
            "query collection cardinality exceeds exact scanner bounds",
            vec![query.request_id.clone()],
        );
    }
    Ok(())
}

fn scan_candidate_capacity(query: &AnchorQuery) -> usize {
    let page = query
        .budget
        .maximum_candidates
        .min(query.budget.maximum_records) as usize;
    page.saturating_mul(usize::from(query.budget.maximum_continuations) + 1)
}

fn gather_exact_identity(
    derived: &DerivedSemanticAnchorCatalogue,
    query: &AnchorQuery,
    entries: &BTreeMap<SemanticId, &IdentityAnchorEntry>,
    accumulators: &mut BTreeMap<SemanticId, CandidateAccumulator>,
    unknown: &mut BTreeSet<String>,
    scan_capacity: usize,
) {
    if !query
        .allowed_channels
        .contains(&AssociationChannel::ExactIdentity)
    {
        return;
    }
    for unit_id in &query.known_identities {
        if let Some(entry) = entries.get(unit_id) {
            let added = add_contribution(
                accumulators,
                &entry.address,
                AssociationContribution {
                    channel: AssociationChannel::ExactIdentity,
                    candidate_address: entry.address.clone(),
                    basis: format!("known identity {}", unit_id),
                    channel_local_value: ChannelLocalValue::Exact,
                    evidence_refs: BTreeSet::from([
                        derived.catalogue.identity.catalogue_id.clone(),
                        unit_id.clone(),
                    ]),
                    conditions: BTreeSet::new(),
                    unresolved_guards: BTreeSet::new(),
                    status: ContributionStatus::Retained,
                },
                scan_capacity,
            );
            debug_assert!(added, "known identity capacity was validated");
        } else {
            unknown.insert(format!("identity:{unit_id}"));
        }
    }
}

fn gather_exact_labels(
    derived: &DerivedSemanticAnchorCatalogue,
    query: &AnchorQuery,
    entries: &BTreeMap<SemanticId, &IdentityAnchorEntry>,
    accumulators: &mut BTreeMap<SemanticId, CandidateAccumulator>,
    unknown: &mut BTreeSet<String>,
    scan_capacity: usize,
) -> bool {
    if !query
        .allowed_channels
        .contains(&AssociationChannel::ExactLabel)
    {
        return false;
    }
    let mut clipped = false;
    for term in &query.term_set {
        let normalized = normalize(term);
        let Some(unit_ids) = derived.exact_label_index.get(&normalized) else {
            unknown.insert(format!("term:{term}"));
            continue;
        };
        for unit_id in unit_ids {
            if let Some(entry) = entries.get(unit_id)
                && !add_contribution(
                    accumulators,
                    &entry.address,
                    AssociationContribution {
                        channel: AssociationChannel::ExactLabel,
                        candidate_address: entry.address.clone(),
                        basis: format!("exact label {term:?} normalized as {normalized:?}"),
                        channel_local_value: ChannelLocalValue::Exact,
                        evidence_refs: BTreeSet::from([unit_id.clone()]),
                        conditions: BTreeSet::new(),
                        unresolved_guards: BTreeSet::new(),
                        status: ContributionStatus::Retained,
                    },
                    scan_capacity,
                )
            {
                clipped = true;
            }
        }
    }
    clipped
}

#[allow(clippy::too_many_arguments)]
fn gather_declared_applicability(
    derived: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
    query: &AnchorQuery,
    entries: &BTreeMap<SemanticId, &IdentityAnchorEntry>,
    accumulators: &mut BTreeMap<SemanticId, CandidateAccumulator>,
    decisions: &mut Vec<String>,
    omissions: &mut Vec<String>,
    scan_capacity: usize,
) -> AnchorScanResult<bool> {
    if derived.catalogue.applicability_bindings.is_empty() {
        omissions.push(
            "declared applicability requested but the validated derived catalogue contains no admitted bindings"
                .to_owned(),
        );
        return Ok(false);
    }
    let mut clipped = false;
    let seed_ids = accumulators
        .iter()
        .filter(|(_, candidate)| is_expandable(&candidate.eligibility))
        .map(|(unit_id, _)| unit_id.clone())
        .collect::<BTreeSet<_>>();
    for binding in &derived.catalogue.applicability_bindings {
        let matching_seeds = seed_ids
            .iter()
            .filter(|seed_id| {
                binding.identity_ref.as_ref() == Some(*seed_id)
                    || binding.admitted_kind.as_ref().is_some_and(|kind| {
                        entries
                            .get(*seed_id)
                            .is_some_and(|entry| &entry.address.kind == kind)
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        if matching_seeds.is_empty() {
            continue;
        }
        let Some(operation) = derived
            .catalogue
            .operation_entries
            .iter()
            .find(|operation| operation.address.unit_id == binding.operation_ref)
        else {
            return scan_fault(
                AnchorScanFaultKind::AddressUnresolved,
                "applicability.operation_ref",
                "binding operation is absent from the validated operation index",
                vec![binding.binding_id.clone(), binding.operation_ref.clone()],
            );
        };
        let Some(entry) = entries.get(&binding.operation_ref).copied() else {
            return Err(unresolved_fault(
                &binding.operation_ref,
                "applicability.identity_entry",
            ));
        };
        if operation.address != entry.address {
            return scan_fault(
                AnchorScanFaultKind::CatalogueMismatch,
                "applicability.operation_address",
                "operation index address differs from its exact identity entry",
                vec![binding.binding_id.clone(), binding.operation_ref.clone()],
            );
        }
        let outcome = gate_identity(entry, derived, fabric, query)?;
        let mut eligibility = outcome.eligibility.clone();
        let mut guards = outcome.unresolved_guards.clone();
        if normalize(&binding.purpose) != normalize(&query.purpose) {
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Excluded);
        }
        let context_inputs = query
            .subject
            .iter()
            .chain(query.use_cases.iter())
            .map(|value| normalize(value))
            .collect::<BTreeSet<_>>();
        if !context_inputs.contains(&normalize(&binding.context)) {
            guards.insert(format!(
                "binding context {:?} lacks an exact query context input",
                binding.context
            ));
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Unresolved);
        }
        if !binding.conditions.is_empty() {
            guards.insert("binding conditions require a separately declared evaluator".to_owned());
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Unresolved);
        }
        if !binding.boundary_refs.is_empty() {
            guards.insert(
                "typed boundary references lack an exact query boundary identity seam".to_owned(),
            );
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Unresolved);
        }
        if binding
            .authority_ref
            .as_ref()
            .is_some_and(|authority| authority != &query.authority_context.caller_id)
        {
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Unauthorized);
        }
        eligibility = merge_eligibility(
            eligibility,
            match binding.status {
                ApplicabilityStatus::Declared | ApplicabilityStatus::Derived => {
                    CandidateEligibility::Eligible
                }
                ApplicabilityStatus::Candidate | ApplicabilityStatus::Unresolved => {
                    CandidateEligibility::Unresolved
                }
                ApplicabilityStatus::Contradicted => CandidateEligibility::Contradicted,
                ApplicabilityStatus::Blocked => CandidateEligibility::Excluded,
                ApplicabilityStatus::Stale => CandidateEligibility::Stale,
            },
        );
        let contribution = AssociationContribution {
            channel: AssociationChannel::DeclaredApplicability,
            candidate_address: operation.address.clone(),
            basis: format!(
                "binding {} from seeds [{}]",
                binding.binding_id,
                matching_seeds
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            channel_local_value: ChannelLocalValue::Declared,
            evidence_refs: binding
                .evidence_refs
                .iter()
                .cloned()
                .chain([binding.binding_id.clone()])
                .collect(),
            conditions: binding.conditions.clone(),
            unresolved_guards: guards.clone(),
            status: ContributionStatus::Retained,
        };
        if !add_contribution(
            accumulators,
            &operation.address,
            contribution,
            scan_capacity,
        ) {
            clipped = true;
            continue;
        }
        let accumulator = accumulators
            .get_mut(&operation.address.unit_id)
            .expect("just inserted operation candidate");
        accumulator.eligibility = merge_eligibility(accumulator.eligibility.clone(), eligibility);
        accumulator.unresolved_guards.extend(guards);
        decisions.extend(outcome.decisions);
        omissions.extend(outcome.omissions);
        decisions.push(format!(
            "applicability {} proposed operation {}",
            binding.binding_id, binding.operation_ref
        ));
    }
    if clipped {
        omissions.push(format!(
            "declared applicability candidates clipped at scan_capacity={scan_capacity}"
        ));
    }
    Ok(clipped)
}

#[allow(clippy::too_many_arguments)]
fn gather_typed_relations(
    derived: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
    query: &AnchorQuery,
    entries: &BTreeMap<SemanticId, &IdentityAnchorEntry>,
    accumulators: &mut BTreeMap<SemanticId, CandidateAccumulator>,
    decisions: &mut Vec<String>,
    omissions: &mut Vec<String>,
    scan_capacity: usize,
) -> AnchorScanResult<bool> {
    if query.allowed_relations.is_empty() || query.budget.maximum_depth == 0 {
        omissions
            .push("typed relation requested with no allowed relation type or depth".to_owned());
        return Ok(false);
    }
    let relations = fabric
        .relations()
        .map(|(_, relation)| (relation.relation_id.clone(), relation))
        .collect::<BTreeMap<_, _>>();
    let seed_ids = accumulators
        .iter()
        .filter(|(_, candidate)| is_expandable(&candidate.eligibility))
        .map(|(unit_id, _)| unit_id.clone())
        .collect::<Vec<_>>();
    let mut path_count = 0_u32;
    let mut clipped = false;

    'seeds: for seed_id in seed_ids {
        let mut queue = VecDeque::from([TraversalState {
            node: seed_id.clone(),
            nodes: vec![seed_id.clone()],
            relations: Vec::new(),
        }]);
        while let Some(state) = queue.pop_front() {
            let depth = u16::try_from(state.relations.len()).unwrap_or(u16::MAX);
            if depth >= query.budget.maximum_depth {
                continue;
            }
            let Some(relation_ids) = derived.relation_adjacency.get(&state.node) else {
                continue;
            };
            for relation_id in relation_ids {
                let relation =
                    relations
                        .get(relation_id)
                        .copied()
                        .ok_or_else(|| AnchorScanFault {
                            kind: AnchorScanFaultKind::AddressUnresolved,
                            stage: "typed_relation".to_owned(),
                            detail: "catalogue adjacency relation is absent from admitted fabric"
                                .to_owned(),
                            related_ids: vec![relation_id.clone()],
                        })?;
                if !query.allowed_relations.contains(&relation.relation_type) {
                    continue;
                }
                let Some(next) = opposite_endpoint(relation, &state.node) else {
                    return scan_fault(
                        AnchorScanFaultKind::CatalogueMismatch,
                        "typed_relation.endpoint",
                        "adjacency lists a relation that does not contain the current endpoint",
                        vec![state.node.clone(), relation_id.clone()],
                    );
                };
                if state.nodes.contains(next) {
                    continue;
                }
                if path_count >= query.budget.maximum_paths {
                    clipped = true;
                    break 'seeds;
                }
                path_count = path_count.saturating_add(1);
                let mut path_relations = state.relations.clone();
                path_relations.push(relation_id.clone());
                let mut path_nodes = state.nodes.clone();
                path_nodes.push(next.clone());
                let entry = entries
                    .get(next)
                    .copied()
                    .ok_or_else(|| unresolved_fault(next, "typed_relation.target"))?;
                let outcome = gate_identity(entry, derived, fabric, query)?;
                let evidence_refs = path_relations.iter().cloned().collect();
                if !add_contribution(
                    accumulators,
                    &entry.address,
                    AssociationContribution {
                        channel: AssociationChannel::TypedRelation,
                        candidate_address: entry.address.clone(),
                        basis: format_relation_basis(
                            &seed_id,
                            &path_nodes,
                            &path_relations,
                            &relations,
                        ),
                        channel_local_value: ChannelLocalValue::RelationHops(
                            u16::try_from(path_relations.len()).unwrap_or(u16::MAX),
                        ),
                        evidence_refs,
                        conditions: BTreeSet::new(),
                        unresolved_guards: outcome.unresolved_guards.clone(),
                        status: ContributionStatus::Retained,
                    },
                    scan_capacity,
                ) {
                    clipped = true;
                    break 'seeds;
                }
                let accumulator = accumulators
                    .get_mut(next)
                    .expect("just inserted relation candidate");
                apply_gate(accumulator, &outcome);
                decisions.extend(outcome.decisions);
                omissions.extend(outcome.omissions);
                if is_expandable(&outcome.eligibility) {
                    queue.push_back(TraversalState {
                        node: next.clone(),
                        nodes: path_nodes,
                        relations: path_relations,
                    });
                }
            }
        }
    }
    if clipped {
        omissions.push(format!(
            "typed relation traversal clipped at maximum_paths={}",
            query.budget.maximum_paths
        ));
    }
    Ok(clipped)
}

fn gate_identity(
    entry: &IdentityAnchorEntry,
    derived: &DerivedSemanticAnchorCatalogue,
    fabric: &SemanticFabric,
    query: &AnchorQuery,
) -> AnchorScanResult<GateOutcome> {
    let unit_id = &entry.address.unit_id;
    let unit = fabric
        .unit(unit_id)
        .ok_or_else(|| unresolved_fault(unit_id, "gate.fabric_unit"))?;
    let package = derived
        .generation
        .packages
        .iter()
        .find(|package| package.package_id == entry.address.package_id)
        .ok_or_else(|| unresolved_fault(&entry.address.package_id, "gate.package"))?;
    let admitted = fabric
        .package_for_unit(unit_id)
        .ok_or_else(|| unresolved_fault(unit_id, "gate.package_owner"))?;
    if admitted.package().package_id != package.package_id
        || package.package_digest != entry.address.package_digest
    {
        return scan_fault(
            AnchorScanFaultKind::CatalogueMismatch,
            "gate.package_identity",
            "candidate package identity differs between catalogue and admitted fabric",
            vec![unit_id.clone(), package.package_id.clone()],
        );
    }

    let mut eligibility = CandidateEligibility::Eligible;
    let mut guards = BTreeSet::new();
    let mut decisions = Vec::new();
    let mut omissions = Vec::new();

    eligibility = merge_eligibility(
        eligibility,
        match (&entry.lifecycle, &unit.status) {
            (AnchorLifecycle::Admitted, UnitStatus::Disputed) => CandidateEligibility::Contradicted,
            (AnchorLifecycle::Admitted, UnitStatus::Unresolved) => CandidateEligibility::Unresolved,
            (AnchorLifecycle::Admitted, _) => CandidateEligibility::Eligible,
            _ => CandidateEligibility::Stale,
        },
    );

    let scope = &package.authority_scope;
    let scope_match = query
        .authority_context
        .allowed_package_scopes
        .iter()
        .any(|allowed| scope.projects.contains(allowed) || scope.namespaces.contains(allowed));
    let capability_match = scope
        .instruction_capabilities
        .contains(&query.authority_context.operation);
    let kind_match = scope.semantic_kinds.contains(&entry.address.kind);
    let perspective_match =
        scope.perspectives.is_empty() || scope.perspectives.contains(&unit.context.perspective);
    if !scope_match || !capability_match || !kind_match || !perspective_match {
        eligibility = merge_eligibility(eligibility, CandidateEligibility::Unauthorized);
        decisions.push(format!(
            "candidate {unit_id} denied by exact package read scope capability kind or perspective"
        ));
    } else {
        decisions.push(format!(
            "candidate {unit_id} passed exact package read authority"
        ));
    }

    if entry.purposes.is_empty() {
        guards.insert("candidate purpose declaration is absent".to_owned());
        eligibility = merge_eligibility(eligibility, CandidateEligibility::Unresolved);
        omissions.push(format!("candidate {unit_id} has no declared purpose"));
    } else if !entry
        .purposes
        .iter()
        .any(|purpose| normalize(purpose) == normalize(&query.purpose))
    {
        eligibility = merge_eligibility(eligibility, CandidateEligibility::Excluded);
        decisions.push(format!("candidate {unit_id} excluded by purpose"));
    } else {
        decisions.push(format!("candidate {unit_id} passed exact purpose"));
    }

    if !query.use_cases.is_empty() {
        let declared_contexts = entry
            .use_cases
            .iter()
            .chain([
                &unit.context.scope,
                &unit.context.perspective,
                &unit.context.world,
            ])
            .map(|value| normalize(value))
            .collect::<BTreeSet<_>>();
        if !query
            .use_cases
            .iter()
            .map(|value| normalize(value))
            .any(|value| declared_contexts.contains(&value))
        {
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Excluded);
            decisions.push(format!("candidate {unit_id} excluded by use-case context"));
        }
    }

    if !query.include_boundaries.is_empty() {
        if entry.included_boundaries.is_empty() {
            guards.insert("candidate has no declared include-boundary contract".to_owned());
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Unresolved);
            omissions.push(format!(
                "candidate {unit_id} cannot prove requested include boundaries"
            ));
        } else if !query
            .include_boundaries
            .iter()
            .all(|boundary| entry.included_boundaries.contains(boundary))
        {
            eligibility = merge_eligibility(eligibility, CandidateEligibility::Excluded);
            decisions.push(format!("candidate {unit_id} excluded by include boundary"));
        }
    }
    if !entry
        .included_boundaries
        .is_disjoint(&query.exclude_boundaries)
        || !entry
            .excluded_boundaries
            .is_disjoint(&query.include_boundaries)
    {
        eligibility = merge_eligibility(eligibility, CandidateEligibility::Excluded);
        decisions.push(format!("candidate {unit_id} excluded by boundary conflict"));
    }
    if !entry
        .protected_identities
        .is_subset(&query.known_identities)
    {
        guards.insert("protected identity set is not fully supplied by caller".to_owned());
        eligibility = merge_eligibility(eligibility, CandidateEligibility::Unresolved);
    }

    Ok(GateOutcome {
        eligibility,
        unresolved_guards: guards,
        decisions,
        omissions,
    })
}

fn apply_gate(accumulator: &mut CandidateAccumulator, outcome: &GateOutcome) {
    accumulator.eligibility =
        merge_eligibility(accumulator.eligibility.clone(), outcome.eligibility.clone());
    accumulator
        .unresolved_guards
        .extend(outcome.unresolved_guards.iter().cloned());
}

fn add_contribution(
    accumulators: &mut BTreeMap<SemanticId, CandidateAccumulator>,
    address: &SemanticAddress,
    contribution: AssociationContribution,
    scan_capacity: usize,
) -> bool {
    if !accumulators.contains_key(&address.unit_id) && accumulators.len() >= scan_capacity {
        return false;
    }
    let accumulator = accumulators
        .entry(address.unit_id.clone())
        .or_insert_with(|| CandidateAccumulator {
            address: address.clone(),
            contributions: Vec::new(),
            eligibility: CandidateEligibility::Eligible,
            unresolved_guards: BTreeSet::new(),
        });
    if !accumulator.contributions.iter().any(|existing| {
        existing.channel == contribution.channel
            && existing.basis == contribution.basis
            && existing.channel_local_value == contribution.channel_local_value
    }) {
        accumulator.contributions.push(contribution);
    }
    true
}

fn finalize_candidates(
    accumulators: BTreeMap<SemanticId, CandidateAccumulator>,
) -> AnchorScanResult<Vec<AnchorCandidate>> {
    let mut candidates = Vec::with_capacity(accumulators.len());
    for (_, mut accumulator) in accumulators {
        accumulator.contributions.sort_by(|left, right| {
            (
                channel_order(&left.channel),
                channel_rank(&left.channel_local_value),
                &left.basis,
            )
                .cmp(&(
                    channel_order(&right.channel),
                    channel_rank(&right.channel_local_value),
                    &right.basis,
                ))
        });
        let Some(best_tier) = accumulator
            .contributions
            .iter()
            .filter(|contribution| contribution.status == ContributionStatus::Retained)
            .map(|contribution| tier_for_channel(&contribution.channel))
            .min()
        else {
            return scan_fault(
                AnchorScanFaultKind::ResultMismatch,
                "candidate.contributions",
                "candidate has no retained contribution",
                vec![accumulator.address.unit_id.clone()],
            );
        };
        let channel_local_rank = accumulator
            .contributions
            .iter()
            .filter(|contribution| {
                contribution.status == ContributionStatus::Retained
                    && tier_for_channel(&contribution.channel) == best_tier
            })
            .map(|contribution| channel_rank(&contribution.channel_local_value))
            .min()
            .unwrap_or(1);
        candidates.push(AnchorCandidate {
            address: accumulator.address,
            contributions: accumulator.contributions,
            priority_tier: best_tier,
            channel_local_rank,
            eligibility: accumulator.eligibility,
            unresolved_guards: accumulator.unresolved_guards,
            exact_resolution_required: true,
        });
    }
    Ok(candidates)
}

fn apply_winning_ambiguity(candidates: &mut [AnchorCandidate], decisions: &mut Vec<String>) {
    let winning = candidates
        .iter()
        .filter(|candidate| candidate.eligibility == CandidateEligibility::Eligible)
        .map(|candidate| {
            (
                candidate.priority_tier.clone(),
                candidate.channel_local_rank,
            )
        })
        .min();
    let Some((tier, rank)) = winning else {
        return;
    };
    let tied = candidates
        .iter()
        .filter(|candidate| {
            candidate.eligibility == CandidateEligibility::Eligible
                && candidate.priority_tier == tier
                && candidate.channel_local_rank == rank
        })
        .count();
    if tied > 1 {
        for candidate in candidates.iter_mut().filter(|candidate| {
            candidate.eligibility == CandidateEligibility::Eligible
                && candidate.priority_tier == tier
                && candidate.channel_local_rank == rank
        }) {
            candidate.eligibility = CandidateEligibility::Ambiguous;
            decisions.push(format!(
                "candidate {} retained in winning-tier ambiguity",
                candidate.address.unit_id
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_bounded_result(
    derived: &DerivedSemanticAnchorCatalogue,
    query: &AnchorQuery,
    input_digest: ContentDigest,
    candidates: Vec<AnchorCandidate>,
    unknown: Vec<String>,
    decisions: Vec<String>,
    omissions: Vec<String>,
    offset: usize,
    ordinal: u16,
    path_clipped: bool,
) -> AnchorScanResult {
    if offset > candidates.len() {
        return scan_fault(
            AnchorScanFaultKind::InvalidContinuation,
            "continuation.offset",
            "continuation offset exceeds canonical candidate set",
            vec![query.request_id.clone()],
        );
    }
    let page_limit = usize::try_from(
        query
            .budget
            .maximum_candidates
            .min(query.budget.maximum_records),
    )
    .unwrap_or(usize::MAX);
    let mut page = candidates
        .iter()
        .skip(offset)
        .take(page_limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut clipped = path_clipped || offset + page.len() < candidates.len();

    loop {
        if page.is_empty() && offset < candidates.len() {
            return scan_fault(
                AnchorScanFaultKind::BudgetTooSmall,
                "budget.maximum_bytes",
                "byte budget cannot contain one candidate and a progressing continuation",
                vec![query.request_id.clone()],
            );
        }
        let next_offset = offset + page.len();
        let continuation = next_cursor(
            derived,
            query,
            &input_digest,
            next_offset,
            ordinal,
            next_offset < candidates.len(),
        )?;
        if next_offset < candidates.len() && continuation.is_none() {
            clipped = true;
        }
        let result = assemble_result(
            derived,
            query,
            input_digest.clone(),
            page.clone(),
            unknown.clone(),
            decisions.clone(),
            omissions.clone(),
            continuation,
            clipped,
        )?;
        let serialized = serde_json::to_vec(&result).map_err(|error| AnchorScanFault {
            kind: AnchorScanFaultKind::Serialization,
            stage: "result_bytes".to_owned(),
            detail: error.to_string(),
            related_ids: vec![query.request_id.clone()],
        })?;
        if serialized.len() <= usize::try_from(query.budget.maximum_bytes).unwrap_or(usize::MAX) {
            return Ok(result);
        }
        if page.is_empty() {
            return scan_fault(
                AnchorScanFaultKind::BudgetTooSmall,
                "budget.maximum_bytes",
                "byte budget cannot contain even an empty proof-bound scan result",
                vec![query.request_id.clone()],
            );
        }
        page.pop();
        clipped = true;
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_result(
    derived: &DerivedSemanticAnchorCatalogue,
    query: &AnchorQuery,
    input_digest: ContentDigest,
    candidates: Vec<AnchorCandidate>,
    unknown: Vec<String>,
    mut decisions: Vec<String>,
    mut omissions: Vec<String>,
    continuation: Option<String>,
    budget_clipped: bool,
) -> AnchorScanResult<AnchorQueryResult> {
    if budget_clipped {
        decisions.push("result is honestly budget-clipped".to_owned());
    }
    decisions.sort();
    decisions.dedup();
    omissions.sort();
    omissions.dedup();

    let mut record_ids = candidates
        .iter()
        .map(|candidate| candidate.address.unit_id.clone())
        .collect::<Vec<_>>();
    record_ids.sort();
    record_ids.dedup();
    let mut source_anchors = candidates
        .iter()
        .flat_map(|candidate| candidate.address.source_anchors.iter().cloned())
        .collect::<Vec<_>>();
    source_anchors.sort_by(source_anchor_order);
    source_anchors.dedup();
    let boundary_account = boundary_account(&candidates, unknown, budget_clipped);
    let mut result = AnchorQueryResult {
        profile: ANCHOR_QUERY_RESULT_PROFILE.to_owned(),
        request_id: query.request_id.clone(),
        catalogue_root: derived.catalogue.identity.catalogue_root.clone(),
        fabric_root: derived.generation.fabric_root.clone(),
        candidates,
        record_ids,
        source_anchors,
        boundary_account,
        proof: AnchorProof {
            catalogue_root: derived.catalogue.identity.catalogue_root.clone(),
            fabric_root: derived.generation.fabric_root.clone(),
            input_digest,
            decisions,
            omissions,
        },
        continuation,
        result_digest: zero_sha256(),
    };
    result.result_digest =
        anchor_query_result_digest(&result).map_err(|fault| AnchorScanFault {
            kind: AnchorScanFaultKind::Serialization,
            stage: fault.field,
            detail: fault.detail,
            related_ids: vec![query.request_id.clone()],
        })?;
    validate_anchor_query_result(&result).map_err(|fault| AnchorScanFault {
        kind: AnchorScanFaultKind::ResultMismatch,
        stage: fault.field,
        detail: fault.detail,
        related_ids: vec![query.request_id.clone()],
    })?;
    Ok(result)
}

fn boundary_account(
    candidates: &[AnchorCandidate],
    mut unknown: Vec<String>,
    budget_clipped: bool,
) -> BoundaryAccount {
    let ids = |eligibility| {
        candidates
            .iter()
            .filter(|candidate| candidate.eligibility == eligibility)
            .map(|candidate| candidate.address.unit_id.clone())
            .collect::<Vec<_>>()
    };
    unknown.sort();
    unknown.dedup();
    BoundaryAccount {
        admitted: ids(CandidateEligibility::Eligible),
        excluded: ids(CandidateEligibility::Excluded),
        ambiguous: ids(CandidateEligibility::Ambiguous),
        contradictory: ids(CandidateEligibility::Contradicted),
        unknown,
        stale: ids(CandidateEligibility::Stale),
        unauthorized: ids(CandidateEligibility::Unauthorized),
        budget_clipped,
    }
}

fn validate_cursor(
    derived: &DerivedSemanticAnchorCatalogue,
    input_digest: &ContentDigest,
    query: &AnchorQuery,
    cursor: Option<&CursorPayload>,
) -> AnchorScanResult<(usize, u16)> {
    let Some(cursor) = cursor else {
        return Ok((0, 0));
    };
    if cursor.profile != EXACT_ANCHOR_SCAN_PROFILE
        || cursor.catalogue_root != derived.catalogue.identity.catalogue_root
        || cursor.fabric_root != derived.generation.fabric_root
        || &cursor.input_digest != input_digest
        || cursor.ordinal == 0
        || cursor.ordinal > query.budget.maximum_continuations
    {
        return scan_fault(
            AnchorScanFaultKind::InvalidContinuation,
            "continuation",
            "continuation profile roots input digest or ordinal do not match the active scan",
            vec![query.request_id.clone()],
        );
    }
    Ok((
        usize::try_from(cursor.offset).unwrap_or(usize::MAX),
        cursor.ordinal,
    ))
}

fn next_cursor(
    derived: &DerivedSemanticAnchorCatalogue,
    query: &AnchorQuery,
    input_digest: &ContentDigest,
    next_offset: usize,
    ordinal: u16,
    more: bool,
) -> AnchorScanResult<Option<String>> {
    if !more || ordinal >= query.budget.maximum_continuations {
        return Ok(None);
    }
    let offset = u32::try_from(next_offset).map_err(|_| AnchorScanFault {
        kind: AnchorScanFaultKind::InvalidContinuation,
        stage: "continuation.offset".to_owned(),
        detail: "candidate offset exceeds cursor representation".to_owned(),
        related_ids: vec![query.request_id.clone()],
    })?;
    let payload = CursorPayload {
        profile: EXACT_ANCHOR_SCAN_PROFILE.to_owned(),
        catalogue_root: derived.catalogue.identity.catalogue_root.clone(),
        fabric_root: derived.generation.fabric_root.clone(),
        input_digest: input_digest.clone(),
        offset,
        ordinal: ordinal.saturating_add(1),
    };
    Ok(Some(encode_cursor(payload)?))
}

fn encode_cursor(payload: CursorPayload) -> AnchorScanResult<String> {
    let envelope = CursorEnvelope {
        commitment: digest_form(CURSOR_DOMAIN, &payload)?,
        payload,
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| AnchorScanFault {
        kind: AnchorScanFaultKind::Serialization,
        stage: "continuation".to_owned(),
        detail: error.to_string(),
        related_ids: Vec::new(),
    })?;
    Ok(hex_encode(&bytes))
}

fn decode_cursor(token: &str) -> AnchorScanResult<CursorPayload> {
    if token.is_empty() || token.len() > MAX_CURSOR_BYTES * 2 {
        return scan_fault(
            AnchorScanFaultKind::InvalidContinuation,
            "continuation",
            "continuation is empty or oversized",
            Vec::new(),
        );
    }
    let bytes = hex_decode(token)?;
    let envelope: CursorEnvelope =
        serde_json::from_slice(&bytes).map_err(|error| AnchorScanFault {
            kind: AnchorScanFaultKind::InvalidContinuation,
            stage: "continuation".to_owned(),
            detail: error.to_string(),
            related_ids: Vec::new(),
        })?;
    let commitment = digest_form(CURSOR_DOMAIN, &envelope.payload)?;
    if envelope.commitment != commitment {
        return scan_fault(
            AnchorScanFaultKind::InvalidContinuation,
            "continuation.commitment",
            "continuation commitment differs",
            Vec::new(),
        );
    }
    Ok(envelope.payload)
}

fn format_relation_basis(
    seed: &SemanticId,
    nodes: &[SemanticId],
    relation_ids: &[SemanticId],
    relations: &BTreeMap<SemanticId, &SemanticRelation>,
) -> String {
    let steps = relation_ids
        .iter()
        .enumerate()
        .map(|(index, relation_id)| {
            let relation = relations
                .get(relation_id)
                .expect("relation path was resolved before formatting");
            let from = &nodes[index];
            let to = &nodes[index + 1];
            let direction = if &relation.source == from && &relation.target == to {
                "forward"
            } else {
                "reverse"
            };
            format!(
                "{}:{:?}:{}:{}>{}",
                relation.relation_id, relation.relation_type, direction, from, to
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    format!("typed relation seed={seed} path={steps}")
}

fn opposite_endpoint<'a>(
    relation: &'a SemanticRelation,
    node: &SemanticId,
) -> Option<&'a SemanticId> {
    if &relation.source == node {
        Some(&relation.target)
    } else if &relation.target == node {
        Some(&relation.source)
    } else {
        None
    }
}

fn is_expandable(eligibility: &CandidateEligibility) -> bool {
    matches!(
        eligibility,
        CandidateEligibility::Eligible | CandidateEligibility::Ambiguous
    )
}

fn merge_eligibility(
    left: CandidateEligibility,
    right: CandidateEligibility,
) -> CandidateEligibility {
    if eligibility_severity(&left) >= eligibility_severity(&right) {
        left
    } else {
        right
    }
}

fn eligibility_severity(eligibility: &CandidateEligibility) -> u8 {
    match eligibility {
        CandidateEligibility::Eligible => 0,
        CandidateEligibility::Ambiguous => 1,
        CandidateEligibility::Unresolved | CandidateEligibility::Unknown => 2,
        CandidateEligibility::Excluded | CandidateEligibility::Clipped => 3,
        CandidateEligibility::Contradicted => 4,
        CandidateEligibility::Unauthorized => 5,
        CandidateEligibility::Stale => 6,
    }
}

fn tier_for_channel(channel: &AssociationChannel) -> PriorityTier {
    match channel {
        AssociationChannel::ExactIdentity => PriorityTier::ExactIdentity,
        AssociationChannel::ExactLabel => PriorityTier::ExactLabel,
        AssociationChannel::DeclaredApplicability => PriorityTier::DeclaredApplicability,
        AssociationChannel::TypedRelation => PriorityTier::TypedRelation,
        AssociationChannel::Lexical => PriorityTier::Lexical,
        AssociationChannel::Embedding => PriorityTier::Embedding,
        AssociationChannel::LearnedRoute => PriorityTier::LearnedRoute,
    }
}

fn channel_order(channel: &AssociationChannel) -> u8 {
    match channel {
        AssociationChannel::ExactIdentity => 0,
        AssociationChannel::ExactLabel => 1,
        AssociationChannel::DeclaredApplicability => 2,
        AssociationChannel::TypedRelation => 3,
        AssociationChannel::Lexical => 4,
        AssociationChannel::Embedding => 5,
        AssociationChannel::LearnedRoute => 6,
    }
}

fn channel_rank(value: &ChannelLocalValue) -> u32 {
    match value {
        ChannelLocalValue::Exact | ChannelLocalValue::Declared => 1,
        ChannelLocalValue::RelationHops(hops) => u32::from(*hops),
        ChannelLocalValue::RelevanceBasisPoints(points) => u32::from(10_000 - *points),
        ChannelLocalValue::LearnedBasisPoints { basis_points, .. } => {
            u32::from(10_000 - *basis_points)
        }
    }
}

fn candidate_order(left: &AnchorCandidate, right: &AnchorCandidate) -> std::cmp::Ordering {
    (
        &left.priority_tier,
        left.channel_local_rank,
        left.address.unit_id.as_str(),
    )
        .cmp(&(
            &right.priority_tier,
            right.channel_local_rank,
            right.address.unit_id.as_str(),
        ))
}

fn source_anchor_order(left: &SourceAnchor, right: &SourceAnchor) -> std::cmp::Ordering {
    (
        &left.package_id,
        &left.file_id,
        &left.unit_id,
        &left.clause_id,
        left.byte_start,
        left.byte_end,
    )
        .cmp(&(
            &right.package_id,
            &right.file_id,
            &right.unit_id,
            &right.clause_id,
            right.byte_start,
            right.byte_end,
        ))
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn zero_sha256() -> ContentDigest {
    ContentDigest {
        algorithm: DIGEST_ALGORITHM.to_owned(),
        value: "0".repeat(64),
    }
}

fn digest_form<T: Serialize>(domain: &str, value: &T) -> AnchorScanResult<ContentDigest> {
    let bytes = serde_json::to_vec(value).map_err(|error| AnchorScanFault {
        kind: AnchorScanFaultKind::Serialization,
        stage: "digest".to_owned(),
        detail: error.to_string(),
        related_ids: Vec::new(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    Ok(ContentDigest {
        algorithm: DIGEST_ALGORITHM.to_owned(),
        value: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> AnchorScanResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return scan_fault(
            AnchorScanFaultKind::InvalidContinuation,
            "continuation",
            "continuation is not even-length hexadecimal",
            Vec::new(),
        );
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| AnchorScanFault {
                kind: AnchorScanFaultKind::InvalidContinuation,
                stage: "continuation".to_owned(),
                detail: error.to_string(),
                related_ids: Vec::new(),
            })?;
            u8::from_str_radix(text, 16).map_err(|error| AnchorScanFault {
                kind: AnchorScanFaultKind::InvalidContinuation,
                stage: "continuation".to_owned(),
                detail: error.to_string(),
                related_ids: Vec::new(),
            })
        })
        .collect()
}

fn unresolved_fault(unit_id: &SemanticId, stage: &str) -> AnchorScanFault {
    AnchorScanFault {
        kind: AnchorScanFaultKind::AddressUnresolved,
        stage: stage.to_owned(),
        detail: format!("semantic address {unit_id} does not exact-resolve"),
        related_ids: vec![unit_id.clone()],
    }
}

fn scan_fault<T>(
    kind: AnchorScanFaultKind,
    stage: &str,
    detail: &str,
    related_ids: Vec<SemanticId>,
) -> AnchorScanResult<T> {
    Err(AnchorScanFault {
        kind,
        stage: stage.to_owned(),
        detail: detail.to_owned(),
        related_ids,
    })
}
