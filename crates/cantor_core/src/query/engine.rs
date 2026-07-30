use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

use crate::{
    BoundaryAccount, CantorQueryRequest, CantorQueryResult, ContentDigest, DetailAccount,
    DetailStatus, PackageProofRecord, ProofBundle, QueryFault, QueryFaultKind, RelationType,
    RelationshipPath, RelationshipStep, RequestedDetailKind, SearchMode, SemanticId, SemanticUnit,
    UnitKind, UnitStatus, VerifiedQuote, sha256_bytes,
};

use super::fabric::{SemanticFabric, normalize};

pub const QUERY_PROTOCOL_VERSION: &str = "cantor-query/0.1";

#[derive(Clone, Debug)]
struct Candidate {
    id: SemanticId,
    score: u32,
    matched_terms: BTreeSet<String>,
    reasons: Vec<String>,
    omitted_reasons: u32,
}

struct RecordProjection {
    records: Vec<SemanticUnit>,
    clipped: bool,
    elapsed_clipped: bool,
    bytes: u64,
    omissions: Vec<String>,
}

pub fn execute_query(
    fabric: &SemanticFabric,
    request: &CantorQueryRequest,
) -> Result<CantorQueryResult, QueryFault> {
    validate_request(request)?;
    let started = Instant::now();
    let mut elapsed_clipped = false;
    let mut faults = Vec::new();
    let mut boundary = BoundaryAccount {
        admitted: Vec::new(),
        excluded: Vec::new(),
        ambiguous: Vec::new(),
        contradictory: Vec::new(),
        unknown: Vec::new(),
        stale: Vec::new(),
        unauthorized: Vec::new(),
        budget_clipped: false,
    };
    let mut decisions = vec!["stage_1_trust: accepted admitted package snapshot".to_owned()];
    let mut candidate_scores: BTreeMap<SemanticId, Candidate> = BTreeMap::new();

    if request.search_modes.contains(&SearchMode::Routed)
        || request.search_modes.contains(&SearchMode::Composed)
    {
        faults.push(QueryFault::new(
            QueryFaultKind::UnsupportedSearchMode,
            "request_validation",
            "learned routed and composed search are not authoritative in deterministic slice 03",
            Vec::new(),
        ));
    }

    for term in &request.term_set {
        if elapsed_budget_exhausted(started, request) {
            elapsed_clipped = true;
            break;
        }
        let mut term_matched = false;
        if let Ok(id) = SemanticId::new(term.clone())
            && fabric.unit(&id).is_some()
        {
            term_matched = true;
            add_candidate(
                &mut candidate_scores,
                id,
                term,
                100,
                format!("exact semantic identity {}", bounded_debug(term)),
            );
        }
        let label_matches = fabric.exact_label(term).cloned().collect::<Vec<_>>();
        for id in label_matches {
            term_matched = true;
            add_candidate(
                &mut candidate_scores,
                id,
                term,
                90,
                format!("exact label or alias {}", bounded_debug(term)),
            );
        }
        if !term_matched && request.search_modes.contains(&SearchMode::Lexical) {
            for unit in fabric.units() {
                if lexical_match(unit, term) {
                    term_matched = true;
                    add_candidate(
                        &mut candidate_scores,
                        unit.unit_id.clone(),
                        term,
                        25,
                        format!("deterministic lexical containment {}", bounded_debug(term)),
                    );
                }
            }
        }
        if !term_matched {
            boundary.unknown.push(bounded_text(term));
            faults.push(QueryFault::new(
                QueryFaultKind::UnknownIdentity,
                "exact_identity",
                format!(
                    "no admitted semantic identity or label matches {}",
                    bounded_debug(term)
                ),
                Vec::new(),
            ));
        }
    }
    decisions.push(format!(
        "stage_2_exact_identity: {} candidate identities",
        candidate_scores.len()
    ));

    let mut contextual = Vec::new();
    for mut candidate in candidate_scores.into_values() {
        if elapsed_budget_exhausted(started, request) {
            elapsed_clipped = true;
            break;
        }
        let unit = fabric.unit(&candidate.id).ok_or_else(|| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "context",
                "candidate identity disappeared from immutable fabric",
                vec![candidate.id.clone()],
            )
        })?;
        let package = fabric.package_for_unit(&candidate.id).ok_or_else(|| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "trust",
                "candidate has no admitted package owner",
                vec![candidate.id.clone()],
            )
        })?;
        if !caller_can_read(package, unit, request) {
            boundary.unauthorized.push(candidate.id.clone());
            faults.push(QueryFault::new(
                QueryFaultKind::Unauthorized,
                "trust",
                format!("caller scope does not authorize {}", candidate.id),
                vec![candidate.id],
            ));
            continue;
        }
        if let Some(reason) = context_exclusion(unit, request) {
            boundary.excluded.push(candidate.id.clone());
            decisions.push(format!(
                "stage_3_context: excluded {}: {reason}",
                candidate.id
            ));
            continue;
        }
        add_context_score(&mut candidate, unit, request);
        contextual.push(candidate);
    }
    contextual.sort_by_key(|candidate| (Reverse(candidate.score), candidate.id.clone()));

    let mut selected = BTreeSet::new();
    let mut ambiguous = BTreeSet::new();
    for term in &request.term_set {
        let matches = contextual
            .iter()
            .filter(|candidate| candidate.matched_terms.contains(term))
            .collect::<Vec<_>>();
        let Some(highest) = matches.iter().map(|candidate| candidate.score).max() else {
            continue;
        };
        let winners = matches
            .into_iter()
            .filter(|candidate| candidate.score == highest)
            .map(|candidate| candidate.id.clone())
            .collect::<Vec<_>>();
        selected.extend(winners.iter().cloned());
        if winners.len() > 1 {
            ambiguous.extend(winners);
        }
    }
    boundary.excluded.extend(
        contextual
            .iter()
            .filter(|candidate| !selected.contains(&candidate.id))
            .map(|candidate| candidate.id.clone()),
    );
    contextual.retain(|candidate| selected.contains(&candidate.id));
    if !ambiguous.is_empty() {
        boundary.ambiguous = ambiguous.iter().cloned().collect();
        faults.push(QueryFault::new(
            QueryFaultKind::Ambiguous,
            "context",
            "one or more terms retain equally applicable contextual meanings",
            ambiguous.into_iter().collect(),
        ));
    }
    decisions.push(format!(
        "stage_3_context: {} applicable candidates",
        contextual.len()
    ));

    let resolved_subjects = contextual
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect::<Vec<_>>();
    boundary.admitted = resolved_subjects.clone();

    let (candidate_paths, traversal_clipped_paths, traversal_elapsed_clipped) =
        traverse_relations(fabric, &resolved_subjects, request, started);
    elapsed_clipped |= traversal_elapsed_clipped;
    if traversal_clipped_paths {
        boundary.budget_clipped = true;
        faults.push(QueryFault::new(
            QueryFaultKind::BudgetExhausted,
            "relationship",
            "relationship traversal reached the path budget",
            Vec::new(),
        ));
    }

    let record_projection = project_records(fabric, &contextual, request, started)?;
    elapsed_clipped |= record_projection.elapsed_clipped;
    if record_projection.clipped {
        boundary.budget_clipped = true;
        faults.push(QueryFault::new(
            QueryFaultKind::BudgetExhausted,
            "projection",
            "record or byte budget clipped applicable records",
            Vec::new(),
        ));
    }
    let (relationship_paths, byte_clipped_paths, path_bytes) = project_relationship_paths(
        candidate_paths,
        request
            .budget
            .maximum_bytes
            .saturating_sub(record_projection.bytes),
    )?;
    if byte_clipped_paths {
        boundary.budget_clipped = true;
        faults.push(QueryFault::new(
            QueryFaultKind::BudgetExhausted,
            "relationship_projection",
            "semantic payload byte budget clipped relationship paths",
            Vec::new(),
        ));
    }
    decisions.push(format!(
        "stage_5_relationship: {} typed paths",
        relationship_paths.len()
    ));

    let contradictory = contradictory_targets(fabric, &relationship_paths);
    if !contradictory.is_empty() {
        boundary.contradictory = contradictory.clone();
        faults.push(QueryFault::new(
            QueryFaultKind::Contradiction,
            "relationship",
            "a returned path contains an explicit contradiction relation",
            contradictory,
        ));
    }

    let quote_budget = request
        .budget
        .maximum_bytes
        .saturating_sub(record_projection.bytes)
        .saturating_sub(path_bytes);
    let (verified_quotes, clipped_quotes) =
        project_quotes(fabric, &resolved_subjects, request, quote_budget)?;
    if clipped_quotes {
        boundary.budget_clipped = true;
        faults.push(QueryFault::new(
            QueryFaultKind::BudgetExhausted,
            "source_projection",
            "semantic payload byte budget clipped verified quotes",
            Vec::new(),
        ));
    }
    if elapsed_clipped {
        boundary.budget_clipped = true;
        faults.push(QueryFault::new(
            QueryFaultKind::BudgetExhausted,
            "elapsed_budget",
            "query execution reached the caller's elapsed-time budget",
            Vec::new(),
        ));
    }
    let mut detail_accounts = build_detail_accounts(
        request,
        &record_projection.records,
        &verified_quotes,
        &relationship_paths,
        record_projection.clipped
            || traversal_clipped_paths
            || byte_clipped_paths
            || clipped_quotes
            || elapsed_clipped,
        &resolved_subjects,
        &request.known_units,
    );
    for account in &detail_accounts {
        if account.status == DetailStatus::ExplicitlyAbsent {
            faults.push(QueryFault::new(
                QueryFaultKind::MissingDetail,
                "projection",
                format!("{:?}: {}", account.kind, account.reason),
                Vec::new(),
            ));
        }
    }
    detail_accounts.sort_by_key(|account| account.kind.clone());

    let package_checks = resolved_subjects
        .iter()
        .filter_map(|id| fabric.package_for_unit(id))
        .map(|package| {
            format!(
                "admitted package {} certificate {} at epoch {}",
                package.package().package_id,
                package.certificate_id(),
                package.admitted_at_epoch_seconds()
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut package_proofs_by_id = BTreeMap::new();
    for unit_id in &resolved_subjects {
        let package = fabric.package_for_unit(unit_id).ok_or_else(|| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "package_proof",
                "resolved unit has no admitted package proof",
                vec![unit_id.clone()],
            )
        })?;
        let certificate = package.package().certificate.as_ref().ok_or_else(|| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "package_proof",
                "admitted package no longer carries its certificate",
                vec![unit_id.clone()],
            )
        })?;
        package_proofs_by_id.insert(
            package.package().package_id.clone(),
            PackageProofRecord {
                package_id: package.package().package_id.clone(),
                certificate_id: certificate.certificate_id.clone(),
                package_digest: certificate.package_digest.clone(),
                semantic_root_digest: certificate.semantic_root_digest.clone(),
                source_root_digest: certificate.source_root_digest.clone(),
                authority_signer_id: certificate.authority_signer_id.clone(),
                compiler_signer_id: certificate.compiler_signer_id.clone(),
                admitted_at_epoch_seconds: package.admitted_at_epoch_seconds(),
            },
        );
    }
    let source_checks = verified_quotes
        .iter()
        .map(|quote| {
            format!(
                "verified {} bytes at {}:{}..{} digest {}",
                quote.text.len(),
                quote.source_anchor.file_id,
                quote.source_anchor.byte_start,
                quote.source_anchor.byte_end,
                quote.source_anchor.span_digest.value
            )
        })
        .collect::<Vec<_>>();
    let exclusions = boundary
        .excluded
        .iter()
        .map(|id| format!("context excluded {id}"))
        .chain(
            boundary
                .unauthorized
                .iter()
                .map(|id| format!("authority excluded {id}")),
        )
        .collect::<Vec<_>>();
    let mut omissions = record_projection.omissions;
    if boundary.budget_clipped {
        omissions.push("one or more projection budgets clipped output".to_owned());
    }
    let deterministic_contributions = contextual
        .iter()
        .map(|candidate| {
            let omission = if candidate.omitted_reasons == 0 {
                String::new()
            } else {
                format!(
                    "; {} additional scoring reasons omitted",
                    candidate.omitted_reasons
                )
            };
            format!(
                "{} score={} [{}{}]",
                candidate.id,
                candidate.score,
                candidate.reasons.join("; "),
                omission
            )
        })
        .collect::<Vec<_>>();
    let pending_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "pending".to_owned(),
    };
    let mut result = CantorQueryResult {
        protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
        request_id: request.request_id.clone(),
        resolved_subjects,
        records: record_projection.records,
        verified_quotes,
        relationship_paths: relationship_paths.clone(),
        boundary_account: boundary,
        deterministic_contributions,
        routed_contributions: Vec::new(),
        proof: ProofBundle {
            package_proofs: package_proofs_by_id.into_values().collect(),
            package_checks,
            source_checks,
            query_decisions: decisions,
            relation_paths: relationship_paths,
            exclusions,
            omissions,
            result_digest: pending_digest.clone(),
        },
        detail_accounts,
        faults,
        continuation: None,
        result_digest: pending_digest,
    };
    let digest = result_digest(&result)?;
    result.result_digest = digest.clone();
    result.proof.result_digest = digest;
    Ok(result)
}

pub fn verify_query_result_digest(result: &CantorQueryResult) -> Result<bool, QueryFault> {
    Ok(result.result_digest == result.proof.result_digest
        && result.result_digest == result_digest(result)?)
}

fn validate_request(request: &CantorQueryRequest) -> Result<(), QueryFault> {
    if request.protocol_version != QUERY_PROTOCOL_VERSION {
        return Err(QueryFault::new(
            QueryFaultKind::InvalidRequest,
            "request_validation",
            format!(
                "protocol {} is unsupported; expected {QUERY_PROTOCOL_VERSION}",
                request.protocol_version
            ),
            Vec::new(),
        ));
    }
    if request.term_set.is_empty()
        || request.term_set.iter().any(|term| term.trim().is_empty())
        || request.purpose.trim().is_empty()
        || request.requested_detail_kinds.is_empty()
        || request
            .subject
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || request
            .description_need
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || request
            .use_case_set
            .iter()
            .chain(request.include_boundary_set.iter())
            .chain(request.exclude_boundary_set.iter())
            .chain(request.criteria.iter())
            .chain(request.source_scopes.iter())
            .chain(request.perspectives.iter())
            .chain(request.authority_context.allowed_package_scopes.iter())
            .any(|value| value.trim().is_empty())
    {
        return Err(QueryFault::new(
            QueryFaultKind::InvalidRequest,
            "request_validation",
            "terms, purpose, requested details, selectors, and authority scopes must be present and nonblank",
            Vec::new(),
        ));
    }
    if request.authority_context.operation != "semantic_read"
        || request.authority_context.effect_boundary != "read_only"
        || request.authority_context.allowed_package_scopes.is_empty()
    {
        return Err(QueryFault::new(
            QueryFaultKind::Unauthorized,
            "request_validation",
            "query authority must explicitly grant semantic_read under a read_only boundary",
            Vec::new(),
        ));
    }
    if request.budget.maximum_records == 0
        || request.budget.maximum_paths == 0
        || request.budget.maximum_bytes == 0
        || request.budget.maximum_elapsed_milliseconds == 0
    {
        return Err(QueryFault::new(
            QueryFaultKind::InvalidRequest,
            "request_validation",
            "record, path, byte, and elapsed budgets must be nonzero",
            Vec::new(),
        ));
    }
    Ok(())
}

fn add_candidate(
    candidates: &mut BTreeMap<SemanticId, Candidate>,
    id: SemanticId,
    term: &str,
    score: u32,
    reason: String,
) {
    let candidate = candidates.entry(id.clone()).or_insert(Candidate {
        id,
        score: 0,
        matched_terms: BTreeSet::new(),
        reasons: Vec::new(),
        omitted_reasons: 0,
    });
    candidate.score = candidate.score.saturating_add(score);
    candidate.matched_terms.insert(term.to_owned());
    push_candidate_reason(candidate, reason);
}

fn push_candidate_reason(candidate: &mut Candidate, reason: String) {
    const MAX_REASONS: usize = 32;
    if candidate.reasons.len() < MAX_REASONS {
        candidate.reasons.push(reason);
    } else {
        candidate.omitted_reasons = candidate.omitted_reasons.saturating_add(1);
    }
}

fn lexical_match(unit: &SemanticUnit, term: &str) -> bool {
    let needle = normalize(term);
    normalize(&unit.expression).contains(&needle)
        || normalize(&unit.meaning).contains(&needle)
        || unit
            .aliases
            .iter()
            .any(|alias| normalize(alias).contains(&needle))
}

fn caller_can_read(
    package: &crate::AdmittedPackage,
    unit: &SemanticUnit,
    request: &CantorQueryRequest,
) -> bool {
    let permitted = &request.authority_context.allowed_package_scopes;
    if permitted.contains("*") || permitted.contains(&unit.context.scope) {
        return true;
    }
    package
        .package()
        .certificate
        .as_ref()
        .is_some_and(|certificate| {
            certificate
                .authority_scope
                .projects
                .iter()
                .chain(certificate.authority_scope.namespaces.iter())
                .any(|scope| permitted.contains(scope))
        })
}

fn context_exclusion(unit: &SemanticUnit, request: &CantorQueryRequest) -> Option<String> {
    if !request.source_scopes.is_empty() && !request.source_scopes.contains(&unit.context.scope) {
        return Some(format!(
            "scope {} is outside requested source scopes",
            bounded_debug(&unit.context.scope)
        ));
    }
    if !request.perspectives.is_empty() && !request.perspectives.contains(&unit.context.perspective)
    {
        return Some(format!(
            "perspective {} is outside requested perspectives",
            bounded_debug(&unit.context.perspective)
        ));
    }
    let surface = context_surface(unit);
    if !request
        .include_boundary_set
        .iter()
        .all(|boundary| surface.contains(&normalize(boundary)))
    {
        return Some("required include boundary is absent".to_owned());
    }
    if let Some(boundary) = request
        .exclude_boundary_set
        .iter()
        .find(|boundary| surface.contains(&normalize(boundary)))
    {
        return Some(format!(
            "matched excluded boundary {}",
            bounded_debug(boundary)
        ));
    }
    if !request
        .criteria
        .iter()
        .all(|criterion| surface.contains(&normalize(criterion)))
    {
        return Some("one or more mandatory criteria are absent".to_owned());
    }
    None
}

fn add_context_score(candidate: &mut Candidate, unit: &SemanticUnit, request: &CantorQueryRequest) {
    let surface = context_surface(unit);
    if let Some(subject) = &request.subject
        && surface.contains(&normalize(subject))
    {
        candidate.score = candidate.score.saturating_add(40);
        push_candidate_reason(
            candidate,
            format!("subject alignment {}", bounded_debug(subject)),
        );
    }
    for use_case in &request.use_case_set {
        if surface.contains(&normalize(use_case)) {
            candidate.score = candidate.score.saturating_add(20);
            push_candidate_reason(
                candidate,
                format!("use-case alignment {}", bounded_debug(use_case)),
            );
        }
    }
    if surface.contains(&normalize(&request.purpose)) {
        candidate.score = candidate.score.saturating_add(10);
        push_candidate_reason(candidate, "purpose alignment".to_owned());
    }
    if let Some(description_need) = &request.description_need
        && surface.contains(&normalize(description_need))
    {
        candidate.score = candidate.score.saturating_add(30);
        push_candidate_reason(
            candidate,
            format!("description alignment {}", bounded_debug(description_need)),
        );
    }
    candidate.score = candidate.score.saturating_add(5);
    push_candidate_reason(candidate, "recognized package authority".to_owned());
}

fn context_surface(unit: &SemanticUnit) -> String {
    normalize(&format!(
        "{} {} {} {} {} {} {}",
        unit.expression,
        unit.meaning,
        unit.context.scope,
        unit.context.purpose,
        unit.context.perspective,
        unit.context.world,
        unit.context.assumptions.join(" ")
    ))
}

fn traverse_relations(
    fabric: &SemanticFabric,
    starts: &[SemanticId],
    request: &CantorQueryRequest,
    started: Instant,
) -> (Vec<RelationshipPath>, bool, bool) {
    let mut paths = Vec::new();
    let mut clipped = false;
    let mut queue = starts
        .iter()
        .cloned()
        .map(|id| RelationshipPath {
            unit_path: vec![id],
            steps: Vec::new(),
        })
        .collect::<VecDeque<_>>();
    while let Some(path) = queue.pop_front() {
        if elapsed_budget_exhausted(started, request) {
            return (paths, clipped, true);
        }
        let depth = path.steps.len();
        if depth >= request.budget.maximum_depth as usize {
            continue;
        }
        let Some(last) = path.unit_path.last() else {
            continue;
        };
        for (package_id, relation) in fabric.relations() {
            if relation.source != *last
                || (!request.relation_types.is_empty()
                    && !request.relation_types.contains(&relation.relation_type))
                || path.unit_path.contains(&relation.target)
            {
                continue;
            }
            let Some(target) = fabric.unit(&relation.target) else {
                continue;
            };
            let Some(target_package) = fabric.package_for_unit(&relation.target) else {
                continue;
            };
            if !caller_can_read(target_package, target, request)
                || context_exclusion(target, request).is_some()
            {
                continue;
            }
            if paths.len() >= request.budget.maximum_paths as usize {
                clipped = true;
                return (paths, clipped, false);
            }
            let mut next = path.clone();
            next.unit_path.push(relation.target.clone());
            next.steps.push(RelationshipStep {
                package_id: package_id.clone(),
                relation_id: relation.relation_id.clone(),
                relation_type: relation.relation_type.clone(),
                source: relation.source.clone(),
                target: relation.target.clone(),
                source_ref: relation.source_ref.clone(),
            });
            paths.push(next.clone());
            queue.push_back(next);
        }
    }
    (paths, clipped, false)
}

fn contradictory_targets(fabric: &SemanticFabric, paths: &[RelationshipPath]) -> Vec<SemanticId> {
    let path_edges = paths
        .iter()
        .flat_map(|path| path.steps.iter())
        .map(|step| (step.source.clone(), step.target.clone()))
        .collect::<BTreeSet<_>>();
    fabric
        .relations()
        .filter(|(_, relation)| {
            relation.relation_type == RelationType::Contradicts
                && path_edges.contains(&(relation.source.clone(), relation.target.clone()))
        })
        .map(|(_, relation)| relation.target.clone())
        .collect()
}

fn project_records(
    fabric: &SemanticFabric,
    candidates: &[Candidate],
    request: &CantorQueryRequest,
    started: Instant,
) -> Result<RecordProjection, QueryFault> {
    let mut records = Vec::new();
    let mut bytes = 0_u64;
    let mut clipped = false;
    let mut omitted_known = Vec::new();
    for candidate in candidates {
        if elapsed_budget_exhausted(started, request) {
            return Ok(RecordProjection {
                records,
                clipped,
                elapsed_clipped: true,
                bytes,
                omissions: omitted_known,
            });
        }
        if request.known_units.contains(&candidate.id) {
            omitted_known.push(format!(
                "known unit {} was resolved but not resent",
                candidate.id
            ));
            continue;
        }
        let unit = fabric.unit(&candidate.id).ok_or_else(|| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "projection",
                "resolved unit is absent from immutable fabric",
                vec![candidate.id.clone()],
            )
        })?;
        let encoded = serde_json::to_vec(unit).map_err(|error| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "projection",
                error.to_string(),
                vec![candidate.id.clone()],
            )
        })?;
        let encoded_len = encoded.len() as u64;
        if records.len() >= request.budget.maximum_records as usize
            || bytes.saturating_add(encoded_len) > request.budget.maximum_bytes
        {
            clipped = true;
            continue;
        }
        bytes = bytes.saturating_add(encoded_len);
        records.push(unit.clone());
    }
    Ok(RecordProjection {
        records,
        clipped,
        elapsed_clipped: false,
        bytes,
        omissions: omitted_known,
    })
}

fn project_relationship_paths(
    candidates: Vec<RelationshipPath>,
    maximum_bytes: u64,
) -> Result<(Vec<RelationshipPath>, bool, u64), QueryFault> {
    let mut paths = Vec::new();
    let mut bytes = 0_u64;
    let mut clipped = false;
    for path in candidates {
        let encoded_len = serde_json::to_vec(&path)
            .map_err(|error| {
                QueryFault::new(
                    QueryFaultKind::ProofGap,
                    "relationship_projection",
                    error.to_string(),
                    Vec::new(),
                )
            })?
            .len() as u64;
        if bytes.saturating_add(encoded_len) > maximum_bytes {
            clipped = true;
            continue;
        }
        bytes = bytes.saturating_add(encoded_len);
        paths.push(path);
    }
    Ok((paths, clipped, bytes))
}

fn project_quotes(
    fabric: &SemanticFabric,
    unit_ids: &[SemanticId],
    request: &CantorQueryRequest,
    maximum_bytes: u64,
) -> Result<(Vec<VerifiedQuote>, bool), QueryFault> {
    let quote_requested = request.requested_detail_kinds.iter().any(|kind| {
        matches!(
            kind,
            RequestedDetailKind::Clause
                | RequestedDetailKind::Definition
                | RequestedDetailKind::Description
                | RequestedDetailKind::Evidence
                | RequestedDetailKind::SourceSpan
        )
    });
    if !quote_requested {
        return Ok((Vec::new(), false));
    }
    let mut verified_quotes = Vec::new();
    let mut bytes = 0_u64;
    let mut clipped = false;
    for unit_id in unit_ids {
        let package = fabric.package_for_unit(unit_id).ok_or_else(|| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "source_proof",
                "resolved subject has no admitted package",
                vec![unit_id.clone()],
            )
        })?;
        let quote = package.quote(unit_id).ok_or_else(|| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "source_proof",
                "resolved subject has no verified quote",
                vec![unit_id.clone()],
            )
        })?;
        let source = package
            .content()
            .sources
            .iter()
            .find(|source| source.file_id == quote.anchor.file_id)
            .ok_or_else(|| {
                QueryFault::new(
                    QueryFaultKind::ProofGap,
                    "source_proof",
                    "verified quote has no signed source snapshot",
                    vec![unit_id.clone()],
                )
            })?;
        let text = String::from_utf8(quote.bytes.clone()).map_err(|error| {
            QueryFault::new(
                QueryFaultKind::ProofGap,
                "source_proof",
                format!("admitted quote is not valid UTF-8: {error}"),
                vec![unit_id.clone()],
            )
        })?;
        let verified = VerifiedQuote {
            text,
            source_anchor: quote.anchor.clone(),
            document_digest: source.document_digest.clone(),
            certificate_id: package.certificate_id().clone(),
            verified: true,
        };
        let encoded_len = serde_json::to_vec(&verified)
            .map_err(|error| {
                QueryFault::new(
                    QueryFaultKind::ProofGap,
                    "source_projection",
                    error.to_string(),
                    vec![unit_id.clone()],
                )
            })
            .map(|bytes| bytes.len() as u64)?;
        if bytes.saturating_add(encoded_len) > maximum_bytes {
            clipped = true;
            continue;
        }
        bytes = bytes.saturating_add(encoded_len);
        verified_quotes.push(verified);
    }
    Ok((verified_quotes, clipped))
}

fn build_detail_accounts(
    request: &CantorQueryRequest,
    records: &[SemanticUnit],
    quotes: &[VerifiedQuote],
    paths: &[RelationshipPath],
    clipped: bool,
    resolved_subjects: &[SemanticId],
    known_units: &BTreeSet<SemanticId>,
) -> Vec<DetailAccount> {
    request
        .requested_detail_kinds
        .iter()
        .map(|kind| {
            let ids: Vec<SemanticId> = match kind {
                RequestedDetailKind::Term
                | RequestedDetailKind::Definition
                | RequestedDetailKind::Description
                | RequestedDetailKind::UseCase
                | RequestedDetailKind::Boundary => records
                    .iter()
                    .map(|record| record.unit_id.clone())
                    .collect(),
                RequestedDetailKind::Clause
                | RequestedDetailKind::Evidence
                | RequestedDetailKind::SourceSpan => quotes
                    .iter()
                    .map(|quote| quote.source_anchor.unit_id.clone())
                    .collect(),
                RequestedDetailKind::Condition => records
                    .iter()
                    .filter(|record| {
                        matches!(record.kind, UnitKind::Contract | UnitKind::Declaration)
                    })
                    .map(|record| record.unit_id.clone())
                    .collect(),
                RequestedDetailKind::Relation => paths
                    .iter()
                    .filter_map(|path| path.unit_path.last().cloned())
                    .collect(),
                RequestedDetailKind::Instruction => records
                    .iter()
                    .filter(|record| matches!(record.kind, UnitKind::Operation | UnitKind::Program))
                    .map(|record| record.unit_id.clone())
                    .collect(),
                RequestedDetailKind::Authority => resolved_subjects.to_vec(),
                RequestedDetailKind::Fault => records
                    .iter()
                    .filter(|record| record.kind == UnitKind::Fault)
                    .map(|record| record.unit_id.clone())
                    .collect(),
                RequestedDetailKind::Derivation => records
                    .iter()
                    .filter(|record| record.status == UnitStatus::Inferred)
                    .map(|record| record.unit_id.clone())
                    .collect(),
            };
            let already_resident = ids.is_empty()
                && matches!(
                    kind,
                    RequestedDetailKind::Term
                        | RequestedDetailKind::Definition
                        | RequestedDetailKind::Description
                        | RequestedDetailKind::UseCase
                        | RequestedDetailKind::Boundary
                )
                && !resolved_subjects.is_empty()
                && resolved_subjects.iter().all(|id| known_units.contains(id));
            let account_ids = if already_resident {
                resolved_subjects.to_vec()
            } else {
                ids
            };
            let status = if !account_ids.is_empty() && !already_resident {
                DetailStatus::Returned
            } else if already_resident {
                DetailStatus::AlreadyResident
            } else if clipped {
                DetailStatus::BudgetClipped
            } else {
                DetailStatus::ExplicitlyAbsent
            };
            let reason = match status {
                DetailStatus::Returned => {
                    "requested detail is present in projected proof".to_owned()
                }
                DetailStatus::AlreadyResident => {
                    "exact resolved unit was declared resident and was not resent".to_owned()
                }
                DetailStatus::BudgetClipped => {
                    "requested detail may exist beyond the active projection budget".to_owned()
                }
                DetailStatus::ExplicitlyAbsent => {
                    "no applicable admitted record supplies this requested detail".to_owned()
                }
            };
            DetailAccount {
                kind: kind.clone(),
                status,
                record_ids: account_ids,
                reason,
            }
        })
        .collect()
}

fn result_digest(result: &CantorQueryResult) -> Result<ContentDigest, QueryFault> {
    let mut normalized = result.clone();
    normalized.result_digest = ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "pending".to_owned(),
    };
    normalized.proof.result_digest = normalized.result_digest.clone();
    let bytes = serde_json::to_vec(&normalized).map_err(|error| {
        QueryFault::new(
            QueryFaultKind::ProofGap,
            "result_digest",
            error.to_string(),
            Vec::new(),
        )
    })?;
    Ok(sha256_bytes(&bytes))
}

fn elapsed_budget_exhausted(started: Instant, request: &CantorQueryRequest) -> bool {
    started.elapsed().as_millis() >= u128::from(request.budget.maximum_elapsed_milliseconds)
}

fn bounded_text(value: &str) -> String {
    const MAX_CHARS: usize = 120;
    let preview = value.chars().take(MAX_CHARS).collect::<String>();
    if preview.len() < value.len() {
        format!("{preview}…[{} bytes]", value.len())
    } else {
        preview
    }
}

fn bounded_debug(value: &str) -> String {
    format!("{:?}", bounded_text(value))
}
