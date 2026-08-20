use std::collections::BTreeSet;

mod common;

use cantor_core::{
    ANCHOR_QUERY_PROFILE, AnchorBudget, AnchorQuery, AnchorScanFaultKind, AssociationChannel,
    AuthorityContext, AuthorityScope, CandidateEligibility, CatalogueDerivationRequest,
    DerivedSemanticAnchorCatalogue, PriorityTier, RelationType, SemanticFabric, SemanticId,
    UnitStatus, admit_package, derive_semantic_anchor_catalogue, scan_exact_semantic_anchors,
    validate_exact_anchor_scan_result,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture id")
}

fn fabric_from_input(input: cantor_core::PackageCompilationInput) -> SemanticFabric {
    let scope = input.authority_scope.clone();
    let compiler = common::compiler("1.0.0");
    let store = common::trust_store(&compiler, "1.0.0", &scope);
    let package = compiler.compile(input).expect("fixture package compiles");
    let admitted =
        admit_package(&package, &store, &scope, common::NOW).expect("fixture package admits");
    SemanticFabric::from_admitted([admitted]).expect("fixture fabric loads")
}

fn fixture_fabric() -> SemanticFabric {
    fabric_from_input(common::package_input(""))
}

fn derive_fixture(fabric: &SemanticFabric) -> DerivedSemanticAnchorCatalogue {
    derive_semantic_anchor_catalogue(
        fabric,
        CatalogueDerivationRequest {
            catalogue_id: id("catalogue:exact_scan_fixture"),
            logical_revision: "exact-scan-r1".to_owned(),
        },
    )
    .expect("fixture catalogue derives")
}

fn scan_query() -> AnchorQuery {
    AnchorQuery {
        profile: ANCHOR_QUERY_PROFILE.to_owned(),
        request_id: id("request:exact_scan_fixture"),
        term_set: BTreeSet::from(["bank".to_owned()]),
        subject: None,
        purpose: "trusted-package fixture".to_owned(),
        use_cases: BTreeSet::new(),
        include_boundaries: BTreeSet::new(),
        exclude_boundaries: BTreeSet::new(),
        known_identities: BTreeSet::new(),
        requested_details: BTreeSet::new(),
        allowed_relations: BTreeSet::new(),
        allowed_channels: BTreeSet::from([AssociationChannel::ExactLabel]),
        authority_context: AuthorityContext {
            caller_id: id("caller:exact_scan_fixture"),
            allowed_package_scopes: BTreeSet::from(["cantor".to_owned()]),
            operation: "read".to_owned(),
            effect_boundary: "read_only".to_owned(),
        },
        budget: AnchorBudget {
            maximum_candidates: 16,
            maximum_records: 16,
            maximum_paths: 16,
            maximum_depth: 4,
            maximum_bytes: 128 * 1024,
            maximum_elapsed_milliseconds: 1_000,
            maximum_continuations: 4,
        },
    }
}

#[test]
fn exact_identity_precedes_label_and_whole_result_rebuilds() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut query = scan_query();
    query
        .allowed_channels
        .insert(AssociationChannel::ExactIdentity);
    query.known_identities.insert(id("unit:bank_financial"));

    let result =
        scan_exact_semantic_anchors(&derived, &fabric, &query, None).expect("exact scan succeeds");
    validate_exact_anchor_scan_result(&derived, &fabric, &query, None, &result)
        .expect("whole result rebuilds");
    assert_eq!(result.candidates.len(), 2);
    assert_eq!(
        result.candidates[0].address.unit_id,
        id("unit:bank_financial")
    );
    assert_eq!(
        result.candidates[0].priority_tier,
        PriorityTier::ExactIdentity
    );
    assert_eq!(
        result.candidates[0].eligibility,
        CandidateEligibility::Eligible
    );
    assert_eq!(result.candidates[1].priority_tier, PriorityTier::ExactLabel);

    let repeated = scan_exact_semantic_anchors(&derived, &fabric, &query, None)
        .expect("repeat exact scan succeeds");
    assert_eq!(
        serde_json::to_vec(&result).expect("result bytes"),
        serde_json::to_vec(&repeated).expect("repeat bytes")
    );
}

#[test]
fn shared_exact_label_remains_explicit_ambiguity() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let result = scan_exact_semantic_anchors(&derived, &fabric, &scan_query(), None)
        .expect("exact label scan succeeds");

    assert_eq!(result.candidates.len(), 2);
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.eligibility == CandidateEligibility::Ambiguous)
    );
    assert_eq!(result.boundary_account.ambiguous.len(), 2);
    assert!(
        result
            .proof
            .decisions
            .iter()
            .any(|decision| decision.contains("winning-tier ambiguity"))
    );
}

#[test]
fn purpose_boundary_authority_and_lifecycle_gates_are_visible() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);

    let mut purpose = scan_query();
    purpose.purpose = "another purpose".to_owned();
    let excluded = scan_exact_semantic_anchors(&derived, &fabric, &purpose, None)
        .expect("purpose mismatch is a disposition");
    assert!(
        excluded
            .candidates
            .iter()
            .all(|candidate| candidate.eligibility == CandidateEligibility::Excluded)
    );

    let mut authority = scan_query();
    authority.authority_context.allowed_package_scopes = BTreeSet::from(["other".to_owned()]);
    let unauthorized = scan_exact_semantic_anchors(&derived, &fabric, &authority, None)
        .expect("authority mismatch is a disposition");
    assert!(
        unauthorized
            .candidates
            .iter()
            .all(|candidate| candidate.eligibility == CandidateEligibility::Unauthorized)
    );

    let mut boundary = scan_query();
    boundary.include_boundaries.insert("signed-only".to_owned());
    let unresolved = scan_exact_semantic_anchors(&derived, &fabric, &boundary, None)
        .expect("missing boundary declaration is unresolved");
    assert!(
        unresolved
            .candidates
            .iter()
            .all(|candidate| candidate.eligibility == CandidateEligibility::Unresolved)
    );
    assert!(
        unresolved
            .proof
            .omissions
            .iter()
            .any(|omission| omission.contains("include boundaries"))
    );

    let mut stale_input = common::package_input("");
    stale_input.units[1].unit.status = UnitStatus::Superseded;
    let stale_fabric = fabric_from_input(stale_input);
    let stale_derived = derive_fixture(&stale_fabric);
    let mut stale_query = scan_query();
    stale_query.term_set = BTreeSet::from(["riverbank".to_owned()]);
    let stale = scan_exact_semantic_anchors(&stale_derived, &stale_fabric, &stale_query, None)
        .expect("stale lifecycle is visible");
    assert_eq!(stale.candidates.len(), 1);
    assert_eq!(stale.candidates[0].eligibility, CandidateEligibility::Stale);
}

#[test]
fn typed_relation_walk_preserves_path_identity_direction_and_hops() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut query = scan_query();
    query.allowed_channels = BTreeSet::from([
        AssociationChannel::ExactIdentity,
        AssociationChannel::TypedRelation,
    ]);
    query.allowed_relations = BTreeSet::from([RelationType::DistinctFrom]);
    query.known_identities.insert(id("unit:bank_financial"));

    let result = scan_exact_semantic_anchors(&derived, &fabric, &query, None)
        .expect("typed relation scan succeeds");
    assert_eq!(result.candidates.len(), 2);
    let related = result
        .candidates
        .iter()
        .find(|candidate| candidate.address.unit_id == id("unit:bank_river"))
        .expect("related identity retained");
    assert_eq!(related.priority_tier, PriorityTier::TypedRelation);
    let contribution = related
        .contributions
        .iter()
        .find(|contribution| contribution.channel == AssociationChannel::TypedRelation)
        .expect("typed relation contribution");
    assert!(
        contribution
            .basis
            .contains("relation:bank_meanings_distinct")
    );
    assert!(contribution.basis.contains("forward"));
    assert!(
        contribution
            .evidence_refs
            .contains(&id("relation:bank_meanings_distinct"))
    );
}

#[test]
fn reverse_relation_walk_is_explicit_and_cycle_free() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut query = scan_query();
    query.allowed_channels = BTreeSet::from([
        AssociationChannel::ExactIdentity,
        AssociationChannel::TypedRelation,
    ]);
    query.allowed_relations = BTreeSet::from([RelationType::DistinctFrom]);
    query.known_identities.insert(id("unit:bank_river"));

    let result = scan_exact_semantic_anchors(&derived, &fabric, &query, None)
        .expect("reverse typed relation scan succeeds");
    assert_eq!(result.candidates.len(), 2);
    let financial = result
        .candidates
        .iter()
        .find(|candidate| candidate.address.unit_id == id("unit:bank_financial"))
        .expect("reverse endpoint retained");
    let contribution = financial
        .contributions
        .iter()
        .find(|contribution| contribution.channel == AssociationChannel::TypedRelation)
        .expect("reverse relation contribution");
    assert!(contribution.basis.contains("reverse"));
    assert_eq!(
        financial
            .contributions
            .iter()
            .filter(|contribution| contribution.channel == AssociationChannel::TypedRelation)
            .count(),
        1
    );
}

#[test]
fn path_budget_clips_without_crossing_disallowed_relations() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut query = scan_query();
    query.allowed_channels = BTreeSet::from([
        AssociationChannel::ExactIdentity,
        AssociationChannel::TypedRelation,
    ]);
    query.allowed_relations = BTreeSet::from([RelationType::DistinctFrom]);
    query.known_identities.insert(id("unit:bank_financial"));
    query.budget.maximum_paths = 0;

    let clipped = scan_exact_semantic_anchors(&derived, &fabric, &query, None)
        .expect("zero path budget returns bounded result");
    assert!(clipped.boundary_account.budget_clipped);
    assert_eq!(clipped.candidates.len(), 1);
    assert!(
        clipped
            .proof
            .omissions
            .iter()
            .any(|omission| omission.contains("maximum_paths=0"))
    );

    let mut disallowed = query;
    disallowed.budget.maximum_paths = 8;
    disallowed.allowed_relations = BTreeSet::from([RelationType::Supports]);
    let bounded = scan_exact_semantic_anchors(&derived, &fabric, &disallowed, None)
        .expect("disallowed relation is not traversed");
    assert_eq!(bounded.candidates.len(), 1);
    assert!(!bounded.boundary_account.budget_clipped);
}

#[test]
fn continuation_is_root_request_and_ordinal_bound() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut query = scan_query();
    query.budget.maximum_candidates = 1;
    query.budget.maximum_records = 1;

    let first =
        scan_exact_semantic_anchors(&derived, &fabric, &query, None).expect("first page succeeds");
    assert_eq!(first.candidates.len(), 1);
    assert!(first.boundary_account.budget_clipped);
    let cursor = first.continuation.as_deref().expect("root-bound cursor");
    let second = scan_exact_semantic_anchors(&derived, &fabric, &query, Some(cursor))
        .expect("second page succeeds");
    assert_eq!(second.candidates.len(), 1);
    assert!(second.continuation.is_none());
    assert_ne!(
        first.candidates[0].address.unit_id,
        second.candidates[0].address.unit_id
    );

    let mut changed_query = query.clone();
    changed_query.purpose.push_str(" changed");
    assert_eq!(
        scan_exact_semantic_anchors(&derived, &fabric, &changed_query, Some(cursor))
            .expect_err("request-bound cursor")
            .kind,
        AnchorScanFaultKind::InvalidContinuation
    );

    let mut changed_cursor = cursor.to_owned();
    changed_cursor.replace_range(
        0..1,
        if &changed_cursor[0..1] == "0" {
            "1"
        } else {
            "0"
        },
    );
    assert_eq!(
        scan_exact_semantic_anchors(&derived, &fabric, &query, Some(&changed_cursor))
            .expect_err("cursor mutation")
            .kind,
        AnchorScanFaultKind::InvalidContinuation
    );
}

#[test]
fn discovery_work_is_bounded_by_page_and_continuation_capacity() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut bounded = scan_query();
    bounded.budget.maximum_candidates = 1;
    bounded.budget.maximum_records = 1;
    bounded.budget.maximum_continuations = 0;
    let result = scan_exact_semantic_anchors(&derived, &fabric, &bounded, None)
        .expect("label discovery clips at one candidate");
    assert_eq!(result.candidates.len(), 1);
    assert!(result.boundary_account.budget_clipped);
    assert!(result.continuation.is_none());

    let mut exact_overflow = bounded;
    exact_overflow.allowed_channels = BTreeSet::from([AssociationChannel::ExactIdentity]);
    exact_overflow.known_identities =
        BTreeSet::from([id("unit:bank_financial"), id("unit:bank_river")]);
    assert_eq!(
        scan_exact_semantic_anchors(&derived, &fabric, &exact_overflow, None)
            .expect_err("explicit identities cannot be silently truncated")
            .kind,
        AnchorScanFaultKind::InvalidQuery
    );
}

#[test]
fn byte_budget_clips_to_a_progressing_candidate_page() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut one_query = scan_query();
    one_query.budget.maximum_candidates = 1;
    one_query.budget.maximum_records = 1;
    let one = scan_exact_semantic_anchors(&derived, &fabric, &one_query, None)
        .expect("one-candidate page");
    let one_bytes = serde_json::to_vec(&one).expect("one-candidate bytes").len();

    let mut byte_query = scan_query();
    byte_query.budget.maximum_bytes = u64::try_from(one_bytes).expect("fixture byte count");
    let clipped = scan_exact_semantic_anchors(&derived, &fabric, &byte_query, None)
        .expect("byte clipping retains a progressing page");
    assert_eq!(clipped.candidates.len(), 1);
    assert!(clipped.boundary_account.budget_clipped);
    assert!(clipped.continuation.is_some());
    assert!(serde_json::to_vec(&clipped).expect("clipped bytes").len() <= one_bytes);
}

#[test]
fn unsupported_channels_and_insufficient_byte_budget_fail_closed() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut unsupported = scan_query();
    unsupported
        .allowed_channels
        .insert(AssociationChannel::Lexical);
    assert_eq!(
        scan_exact_semantic_anchors(&derived, &fabric, &unsupported, None)
            .expect_err("lexical remains locked")
            .kind,
        AnchorScanFaultKind::UnsupportedChannel
    );

    let mut tiny = scan_query();
    tiny.budget.maximum_bytes = 1;
    assert_eq!(
        scan_exact_semantic_anchors(&derived, &fabric, &tiny, None)
            .expect_err("empty proof cannot fit")
            .kind,
        AnchorScanFaultKind::BudgetTooSmall
    );
}

#[test]
fn unavailable_declared_applicability_is_an_explicit_omission() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut query = scan_query();
    query
        .allowed_channels
        .insert(AssociationChannel::DeclaredApplicability);
    let result = scan_exact_semantic_anchors(&derived, &fabric, &query, None)
        .expect("missing structured applicability does not invent candidates");
    assert!(
        result
            .proof
            .omissions
            .iter()
            .any(|omission| { omission.contains("contains no admitted bindings") })
    );
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.priority_tier == PriorityTier::ExactLabel)
    );
}

#[test]
fn stale_catalogue_unknown_inputs_and_result_mutations_are_accounted() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);

    let mut unknown_query = scan_query();
    unknown_query.term_set = BTreeSet::from(["absent".to_owned()]);
    unknown_query
        .allowed_channels
        .insert(AssociationChannel::ExactIdentity);
    unknown_query.known_identities.insert(id("unit:absent"));
    let unknown = scan_exact_semantic_anchors(&derived, &fabric, &unknown_query, None)
        .expect("unknown inputs produce bounded account");
    assert!(unknown.candidates.is_empty());
    assert_eq!(
        unknown.boundary_account.unknown,
        vec!["identity:unit:absent".to_owned(), "term:absent".to_owned()]
    );

    let mut stale = derived.clone();
    stale
        .catalogue
        .identity
        .catalogue_root
        .value
        .replace_range(0..1, "f");
    assert_eq!(
        scan_exact_semantic_anchors(&stale, &fabric, &scan_query(), None)
            .expect_err("stale root")
            .kind,
        AnchorScanFaultKind::CatalogueMismatch
    );

    let query = scan_query();
    let mut result =
        scan_exact_semantic_anchors(&derived, &fabric, &query, None).expect("baseline result");
    result.proof.decisions.push("invented decision".to_owned());
    assert_eq!(
        validate_exact_anchor_scan_result(&derived, &fabric, &query, None, &result)
            .expect_err("mutated result")
            .kind,
        AnchorScanFaultKind::ResultMismatch
    );
}

#[test]
fn context_use_case_is_checked_from_admitted_structured_context() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);
    let mut query = scan_query();
    query.term_set = BTreeSet::from(["riverbank".to_owned()]);
    query.use_cases = BTreeSet::from(["geography".to_owned()]);
    let matching = scan_exact_semantic_anchors(&derived, &fabric, &query, None)
        .expect("structured scope matches");
    assert_eq!(
        matching.candidates[0].eligibility,
        CandidateEligibility::Eligible
    );

    query.use_cases = BTreeSet::from(["finance".to_owned()]);
    let excluded = scan_exact_semantic_anchors(&derived, &fabric, &query, None)
        .expect("structured scope mismatch is visible");
    assert_eq!(
        excluded.candidates[0].eligibility,
        CandidateEligibility::Excluded
    );
}

#[test]
fn read_capability_is_checked_against_signed_package_scope() {
    let mut input = common::package_input("");
    input.authority_scope = AuthorityScope {
        instruction_capabilities: BTreeSet::from(["inspect".to_owned()]),
        ..input.authority_scope
    };
    let fabric = fabric_from_input(input);
    let derived = derive_fixture(&fabric);
    let result = scan_exact_semantic_anchors(&derived, &fabric, &scan_query(), None)
        .expect("capability mismatch is a disposition");
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.eligibility == CandidateEligibility::Unauthorized)
    );
}
