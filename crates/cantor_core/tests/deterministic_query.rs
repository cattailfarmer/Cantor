mod common;

use std::collections::BTreeSet;
use std::time::Instant;

use cantor_core::{
    AuthorityContext, CantorQueryRequest, DetailStatus, QUERY_PROTOCOL_VERSION, QueryBudget,
    QueryFaultKind, RelationType, RequestedDetailKind, SearchMode, SemanticFabric, UnitKind,
    admit_package, execute_query, verify_query_result_digest,
};

use common::{NOW, compiler, id, package_input, scope, trust_store};

fn fabric() -> SemanticFabric {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("query fixture package must compile");
    let store = trust_store(&compiler, "1.0.0", &scope());
    let admitted =
        admit_package(&package, &store, &scope(), NOW).expect("query fixture package must admit");
    SemanticFabric::from_admitted([admitted]).expect("fixture fabric must load")
}

fn request(term: &str) -> CantorQueryRequest {
    CantorQueryRequest {
        protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
        request_id: id("query:deterministic_fixture"),
        term_set: [term.to_owned()].into_iter().collect(),
        subject: None,
        purpose: "resolve the intended meaning".to_owned(),
        use_case_set: BTreeSet::new(),
        include_boundary_set: BTreeSet::new(),
        exclude_boundary_set: BTreeSet::new(),
        description_need: None,
        requested_detail_kinds: [
            RequestedDetailKind::Term,
            RequestedDetailKind::Definition,
            RequestedDetailKind::SourceSpan,
        ]
        .into_iter()
        .collect(),
        search_modes: [
            SearchMode::Exact,
            SearchMode::Contextual,
            SearchMode::Relational,
        ]
        .into_iter()
        .collect(),
        relation_types: BTreeSet::new(),
        criteria: BTreeSet::new(),
        source_scopes: BTreeSet::new(),
        perspectives: BTreeSet::new(),
        known_units: BTreeSet::new(),
        authority_context: AuthorityContext {
            caller_id: id("caller:query_fixture"),
            allowed_package_scopes: ["cantor".to_owned()].into_iter().collect(),
            operation: "semantic_read".to_owned(),
            effect_boundary: "read_only".to_owned(),
        },
        budget: QueryBudget {
            maximum_records: 8,
            maximum_paths: 8,
            maximum_depth: 2,
            maximum_bytes: 32_768,
            maximum_elapsed_milliseconds: 1_000,
        },
    }
}

#[test]
fn contextual_query_selects_financial_bank_and_verifies_source() {
    let fabric = fabric();
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.use_case_set.insert("deposits".to_owned());
    query.source_scopes.insert("finance".to_owned());
    let result = execute_query(&fabric, &query).expect("contextual query must execute");

    assert_eq!(result.resolved_subjects, vec![id("unit:bank_financial")]);
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.verified_quotes.len(), 1);
    assert!(result.verified_quotes[0].verified);
    assert_eq!(
        result.verified_quotes[0].source_anchor.package_id,
        result.proof.package_proofs[0].package_id
    );
    assert_eq!(
        result.verified_quotes[0].certificate_id,
        result.proof.package_proofs[0].certificate_id
    );
    assert_eq!(
        result.verified_quotes[0].document_digest.algorithm,
        "sha256"
    );
    assert!(
        result.verified_quotes[0]
            .text
            .contains("financial institution")
    );
    assert_eq!(
        result.boundary_account.excluded,
        vec![id("unit:bank_river")]
    );
    assert!(verify_query_result_digest(&result).expect("digest must be computable"));
}

#[test]
fn admitted_signed_exact_index_is_the_normalized_lookup_surface() {
    let compiler = compiler("1.0.0");
    let mut input = package_input("");
    input.units[0]
        .unit
        .aliases
        .insert("  deposit-bank  ".to_owned());
    let package = compiler
        .compile(input)
        .expect("normalized exact-index fixture must compile");
    assert!(
        package
            .content
            .exact_indexes
            .labels
            .contains_key("deposit-bank")
    );
    let admitted = admit_package(
        &package,
        &trust_store(&compiler, "1.0.0", &scope()),
        &scope(),
        NOW,
    )
    .expect("normalized exact-index fixture must admit");
    let fabric = SemanticFabric::from_admitted([admitted]).expect("admitted exact index must load");
    let result =
        execute_query(&fabric, &request("deposit-bank")).expect("indexed alias must resolve");
    assert_eq!(result.resolved_subjects, vec![id("unit:bank_financial")]);
}

#[test]
fn empty_term_is_invalid_instead_of_becoming_a_lexical_wildcard() {
    let mut query = request("   ");
    query.search_modes.insert(SearchMode::Lexical);
    let fault = execute_query(&fabric(), &query)
        .expect_err("whitespace term must fail before candidate selection");
    assert_eq!(fault.kind, QueryFaultKind::InvalidRequest);
    assert_eq!(fault.stage, "request_validation");
}

#[test]
fn unresolved_context_preserves_both_meanings_as_ambiguity() {
    let result = execute_query(&fabric(), &request("bank")).expect("query must execute");

    assert_eq!(result.resolved_subjects.len(), 2);
    assert_eq!(result.boundary_account.ambiguous.len(), 2);
    assert!(
        result
            .faults
            .iter()
            .any(|fault| fault.kind == QueryFaultKind::Ambiguous)
    );
}

#[test]
fn excluded_meaning_is_not_reintroduced_by_relation_traversal() {
    let fabric = fabric();
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.exclude_boundary_set.insert("geography".to_owned());
    query.relation_types.insert(RelationType::DistinctFrom);
    let result = execute_query(&fabric, &query).expect("query must execute");

    assert_eq!(result.resolved_subjects, vec![id("unit:bank_financial")]);
    assert!(result.relationship_paths.is_empty());
    assert!(
        result
            .boundary_account
            .excluded
            .contains(&id("unit:bank_river"))
    );
}

#[test]
fn typed_relation_path_is_returned_with_package_proof() {
    let fabric = fabric();
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.relation_types.insert(RelationType::DistinctFrom);
    query
        .requested_detail_kinds
        .insert(RequestedDetailKind::Relation);
    let result = execute_query(&fabric, &query).expect("query must execute");

    assert_eq!(result.relationship_paths.len(), 1);
    assert_eq!(
        result.relationship_paths[0].unit_path,
        vec![id("unit:bank_financial"), id("unit:bank_river")]
    );
    assert_eq!(result.relationship_paths[0].steps.len(), 1);
    assert_eq!(
        result.relationship_paths[0].steps[0].relation_type,
        RelationType::DistinctFrom
    );
    assert_eq!(
        result.relationship_paths[0].steps[0].relation_id,
        id("relation:bank_meanings_distinct")
    );
    assert_eq!(result.proof.relation_paths, result.relationship_paths);
    assert_eq!(result.proof.package_checks.len(), 1);
    assert_eq!(result.proof.package_proofs.len(), 1);
    assert!(
        result
            .detail_accounts
            .iter()
            .any(|account| account.kind == RequestedDetailKind::Relation
                && account.status == DetailStatus::Returned)
    );
}

#[test]
fn every_requested_detail_is_returned_or_explicitly_accounted_absent() {
    let fabric = fabric();
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.requested_detail_kinds.extend([
        RequestedDetailKind::Condition,
        RequestedDetailKind::Instruction,
    ]);
    let result = execute_query(&fabric, &query).expect("query must execute");

    assert_eq!(
        result.detail_accounts.len(),
        query.requested_detail_kinds.len()
    );
    for kind in [
        RequestedDetailKind::Condition,
        RequestedDetailKind::Instruction,
    ] {
        assert!(result.detail_accounts.iter().any(
            |account| account.kind == kind && account.status == DetailStatus::ExplicitlyAbsent
        ));
    }
    assert_eq!(
        result
            .faults
            .iter()
            .filter(|fault| fault.kind == QueryFaultKind::MissingDetail)
            .count(),
        2
    );
}

#[test]
fn unknown_identity_is_visible_without_becoming_invalid_request() {
    let result =
        execute_query(&fabric(), &request("unrepresented-term")).expect("query must execute");

    assert_eq!(
        result.boundary_account.unknown,
        vec!["unrepresented-term".to_owned()]
    );
    assert!(result.records.is_empty());
    assert!(
        result
            .faults
            .iter()
            .any(|fault| fault.kind == QueryFaultKind::UnknownIdentity)
    );

    let long_term = "x".repeat(2_000);
    let result =
        execute_query(&fabric(), &request(&long_term)).expect("long unknown term must execute");
    assert!(result.boundary_account.unknown[0].len() < 256);
    assert!(result.faults[0].message.len() < 512);
}

#[test]
fn record_budget_clipping_is_visible_and_digest_bound() {
    let mut query = request("bank");
    query.budget.maximum_records = 1;
    let result = execute_query(&fabric(), &query).expect("query must execute");

    assert_eq!(result.records.len(), 1);
    assert!(result.boundary_account.budget_clipped);
    assert!(
        result
            .faults
            .iter()
            .any(|fault| fault.kind == QueryFaultKind::BudgetExhausted)
    );
    assert!(verify_query_result_digest(&result).expect("digest must verify"));
}

#[test]
fn elapsed_budget_clipping_is_visible() {
    let mut query = request("bank");
    query.term_set = (0..20_000)
        .map(|index| format!("unknown-term-{index:05}"))
        .collect();
    query.budget.maximum_elapsed_milliseconds = 1;
    let result =
        execute_query(&fabric(), &query).expect("bounded query must return partial result");

    assert!(result.boundary_account.budget_clipped);
    assert!(
        result
            .faults
            .iter()
            .any(|fault| fault.kind == QueryFaultKind::BudgetExhausted
                && fault.stage == "elapsed_budget")
    );
}

#[test]
fn authority_detail_tracks_package_proof_even_when_record_projection_clips() {
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.source_scopes.insert("finance".to_owned());
    query.requested_detail_kinds = [RequestedDetailKind::Authority].into_iter().collect();
    query.budget.maximum_bytes = 1;
    let result = execute_query(&fabric(), &query).expect("bounded authority query must execute");

    assert!(result.records.is_empty());
    assert_eq!(result.proof.package_proofs.len(), 1);
    assert_eq!(result.detail_accounts.len(), 1);
    assert_eq!(
        result.detail_accounts[0].kind,
        RequestedDetailKind::Authority
    );
    assert_eq!(result.detail_accounts[0].status, DetailStatus::Returned);
    assert_eq!(
        result.detail_accounts[0].record_ids,
        vec![id("unit:bank_financial")]
    );
}

#[test]
fn typed_paths_share_the_semantic_payload_byte_budget() {
    let fabric = fabric();
    let record_bytes = serde_json::to_vec(
        fabric
            .unit(&id("unit:bank_financial"))
            .expect("fixture unit must exist"),
    )
    .expect("fixture unit must encode")
    .len() as u64;
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.requested_detail_kinds = [RequestedDetailKind::Term].into_iter().collect();
    query.budget.maximum_bytes = record_bytes;
    let result = execute_query(&fabric, &query).expect("bounded path query must execute");

    assert_eq!(result.records.len(), 1);
    assert!(result.relationship_paths.is_empty());
    assert!(
        result
            .faults
            .iter()
            .any(|fault| fault.stage == "relationship_projection"
                && fault.kind == QueryFaultKind::BudgetExhausted)
    );
}

#[test]
fn verified_quotes_share_the_semantic_payload_byte_budget() {
    let fabric = fabric();
    let record_bytes = serde_json::to_vec(
        fabric
            .unit(&id("unit:bank_financial"))
            .expect("fixture unit must exist"),
    )
    .expect("fixture unit must encode")
    .len() as u64;
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.budget.maximum_depth = 0;
    query.budget.maximum_bytes = record_bytes;
    let result = execute_query(&fabric, &query).expect("bounded quote query must execute");

    assert_eq!(result.records.len(), 1);
    assert!(result.verified_quotes.is_empty());
    assert!(
        result
            .faults
            .iter()
            .any(|fault| fault.stage == "source_projection"
                && fault.kind == QueryFaultKind::BudgetExhausted)
    );
    assert!(
        result
            .detail_accounts
            .iter()
            .any(|account| account.kind == RequestedDetailKind::SourceSpan
                && account.status == DetailStatus::BudgetClipped)
    );
}

#[test]
fn known_unit_is_resolved_but_not_resent() {
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    query.known_units.insert(id("unit:bank_financial"));
    let result = execute_query(&fabric(), &query).expect("query must execute");

    assert_eq!(result.resolved_subjects, vec![id("unit:bank_financial")]);
    assert!(result.records.is_empty());
    assert_eq!(result.verified_quotes.len(), 1);
    assert!(
        result
            .proof
            .omissions
            .iter()
            .any(|entry| entry.contains("not resent"))
    );
    assert!(
        result
            .detail_accounts
            .iter()
            .any(|account| account.kind == RequestedDetailKind::Term
                && account.status == DetailStatus::AlreadyResident)
    );
    assert!(
        result
            .detail_accounts
            .iter()
            .any(|account| account.kind == RequestedDetailKind::SourceSpan
                && account.status == DetailStatus::Returned)
    );
}

#[test]
fn multiple_terms_can_reinforce_one_identity_without_false_unknowns() {
    let mut query = request("bank");
    query.term_set.insert("financial institution".to_owned());
    let result = execute_query(&fabric(), &query).expect("multi-term query must execute");

    assert_eq!(result.resolved_subjects, vec![id("unit:bank_financial")]);
    assert!(result.boundary_account.unknown.is_empty());
    assert!(
        result
            .faults
            .iter()
            .all(|fault| fault.kind != QueryFaultKind::UnknownIdentity)
    );
}

#[test]
fn scoring_explanation_growth_is_bounded_without_changing_resolution() {
    let compiler = compiler("1.0.0");
    let mut input = package_input("");
    let aliases = (0..40)
        .map(|index| format!("financial-alias-{index:02}"))
        .collect::<BTreeSet<_>>();
    input.units[0].unit.aliases.extend(aliases.clone());
    let package = compiler
        .compile(input)
        .expect("bounded-explanation fixture must compile");
    let admitted = admit_package(
        &package,
        &trust_store(&compiler, "1.0.0", &scope()),
        &scope(),
        NOW,
    )
    .expect("bounded-explanation fixture must admit");
    let fabric =
        SemanticFabric::from_admitted([admitted]).expect("bounded-explanation fabric must load");
    let mut query = request("financial-alias-00");
    query.term_set = aliases;
    let result = execute_query(&fabric, &query).expect("many-alias query must execute");

    assert_eq!(result.resolved_subjects, vec![id("unit:bank_financial")]);
    assert_eq!(result.deterministic_contributions.len(), 1);
    assert!(result.deterministic_contributions[0].contains("additional scoring reasons omitted"));
    assert!(result.deterministic_contributions[0].len() < 4_096);
}

#[test]
fn independently_named_terms_resolve_as_multiple_subjects_not_ambiguity() {
    let mut query = request("financial institution");
    query.term_set.insert("riverbank".to_owned());
    let result = execute_query(&fabric(), &query).expect("multi-subject query must execute");

    assert_eq!(
        result.resolved_subjects,
        vec![id("unit:bank_financial"), id("unit:bank_river")]
    );
    assert!(result.boundary_account.ambiguous.is_empty());
    assert!(
        result
            .faults
            .iter()
            .all(|fault| fault.kind != QueryFaultKind::Ambiguous)
    );
}

#[test]
fn criteria_and_description_need_are_active_query_inputs() {
    let fabric = fabric();
    let mut criteria = request("bank");
    criteria.criteria.insert("geography".to_owned());
    let geography = execute_query(&fabric, &criteria).expect("criteria query must execute");
    assert_eq!(geography.resolved_subjects, vec![id("unit:bank_river")]);

    let mut description = request("bank");
    description.description_need = Some("receives deposits".to_owned());
    let financial = execute_query(&fabric, &description).expect("description query must execute");
    assert_eq!(financial.resolved_subjects, vec![id("unit:bank_financial")]);
}

#[test]
fn lexical_search_is_deterministic_and_only_runs_when_requested() {
    let fabric = fabric();
    let mut lexical = request("deposits");
    lexical.search_modes.insert(SearchMode::Lexical);
    let result = execute_query(&fabric, &lexical).expect("lexical query must execute");
    assert_eq!(result.resolved_subjects, vec![id("unit:bank_financial")]);

    let exact_only =
        execute_query(&fabric, &request("deposits")).expect("exact query must execute");
    assert!(exact_only.resolved_subjects.is_empty());
}

#[test]
fn invalid_protocol_and_write_capability_fail_before_querying() {
    let fabric = fabric();
    let mut bad_protocol = request("bank");
    bad_protocol.protocol_version = "cantor-query/9".to_owned();
    let fault = execute_query(&fabric, &bad_protocol).expect_err("protocol must fail");
    assert_eq!(fault.kind, QueryFaultKind::InvalidRequest);

    let mut write = request("bank");
    write.authority_context.effect_boundary = "write".to_owned();
    let fault = execute_query(&fabric, &write).expect_err("write authority must fail");
    assert_eq!(fault.kind, QueryFaultKind::Unauthorized);

    let mut no_details = request("bank");
    no_details.requested_detail_kinds.clear();
    let fault = execute_query(&fabric, &no_details).expect_err("detail demand is required");
    assert_eq!(fault.kind, QueryFaultKind::InvalidRequest);

    let mut blank_description = request("bank");
    blank_description.description_need = Some(" ".to_owned());
    let fault = execute_query(&fabric, &blank_description).expect_err("blank selector must fail");
    assert_eq!(fault.kind, QueryFaultKind::InvalidRequest);
}

#[test]
fn caller_scope_can_exclude_every_matching_record_without_hiding_the_fault() {
    let mut query = request("bank");
    query.authority_context.allowed_package_scopes =
        ["unrelated-project".to_owned()].into_iter().collect();
    let result = execute_query(&fabric(), &query).expect("query must execute");

    assert!(result.records.is_empty());
    assert_eq!(result.boundary_account.unauthorized.len(), 2);
    assert_eq!(
        result
            .faults
            .iter()
            .filter(|fault| fault.kind == QueryFaultKind::Unauthorized)
            .count(),
        2
    );
}

#[test]
fn fabric_rejects_duplicate_semantic_identity_across_packages() {
    let compiler = compiler("1.0.0");
    let first = compiler
        .compile(package_input(""))
        .expect("first package must compile");
    let second = compiler
        .compile(package_input("# shifted\n"))
        .expect("second package must compile");
    let store = trust_store(&compiler, "1.0.0", &scope());
    let first = admit_package(&first, &store, &scope(), NOW).expect("first must admit");
    let second = admit_package(&second, &store, &scope(), NOW).expect("second must admit");
    let fault =
        SemanticFabric::from_admitted([first, second]).expect_err("duplicate IDs must fail");
    assert_eq!(fault.kind, QueryFaultKind::Ambiguous);
}

#[test]
fn fabric_rejects_duplicate_relation_identity_across_packages() {
    let compiler = compiler("1.0.0");
    let first = compiler
        .compile(package_input(""))
        .expect("first relation package must compile");
    let mut second_input = package_input("# independent package\n");
    second_input.units[0].unit.unit_id = id("unit:second_financial");
    second_input.units[1].unit.unit_id = id("unit:second_river");
    second_input.relations[0].source = id("unit:second_financial");
    second_input.relations[0].target = id("unit:second_river");
    let second = compiler
        .compile(second_input)
        .expect("second relation package must compile");
    let store = trust_store(&compiler, "1.0.0", &scope());
    let first = admit_package(&first, &store, &scope(), NOW).expect("first must admit");
    let second = admit_package(&second, &store, &scope(), NOW).expect("second must admit");
    let fault = SemanticFabric::from_admitted([first, second])
        .expect_err("global relation identity collision must fail");
    assert_eq!(fault.kind, QueryFaultKind::Ambiguous);
    assert_eq!(fault.stage, "fabric_load");
}

#[test]
fn condition_and_instruction_records_are_selected_by_typed_detail() {
    let compiler = compiler("1.0.0");
    let mut input = package_input("");
    input.units[0].unit.kind = UnitKind::Contract;
    input.units[1].unit.kind = UnitKind::Operation;
    input.authority_scope.semantic_kinds = [UnitKind::Contract, UnitKind::Operation]
        .into_iter()
        .collect();
    let package = compiler.compile(input).expect("typed package must compile");
    let mut typed_scope = scope();
    typed_scope.semantic_kinds = [UnitKind::Contract, UnitKind::Operation]
        .into_iter()
        .collect();
    let store = trust_store(&compiler, "1.0.0", &typed_scope);
    let admitted =
        admit_package(&package, &store, &typed_scope, NOW).expect("typed package must admit");
    let fabric = SemanticFabric::from_admitted([admitted]).expect("typed fabric must load");
    let mut query = request("bank");
    query.requested_detail_kinds.extend([
        RequestedDetailKind::Condition,
        RequestedDetailKind::Instruction,
    ]);
    let result = execute_query(&fabric, &query).expect("typed query must execute");

    assert!(
        result
            .detail_accounts
            .iter()
            .any(|account| account.kind == RequestedDetailKind::Condition
                && account.status == DetailStatus::Returned)
    );
    assert!(
        result
            .detail_accounts
            .iter()
            .any(|account| account.kind == RequestedDetailKind::Instruction
                && account.status == DetailStatus::Returned)
    );
}

#[test]
fn repeated_execution_is_byte_equivalent_and_fixture_baseline_is_measured() {
    let fabric = fabric();
    let mut query = request("bank");
    query.subject = Some("finance".to_owned());
    let first = execute_query(&fabric, &query).expect("first query must execute");
    let second = execute_query(&fabric, &query).expect("second query must execute");
    assert_eq!(
        serde_json::to_vec(&first).expect("first result must encode"),
        serde_json::to_vec(&second).expect("second result must encode")
    );

    let metrics = fabric.metrics().expect("fabric metrics must be available");
    assert_eq!(metrics.package_count, 1);
    assert_eq!(metrics.semantic_unit_count, 2);
    assert_eq!(metrics.relation_count, 1);
    assert!(metrics.signed_source_bytes > 0);
    assert!(metrics.serialized_package_bytes > metrics.signed_source_bytes);

    let started = Instant::now();
    for _ in 0..1_000 {
        let result = execute_query(&fabric, &query).expect("baseline query must execute");
        assert!(verify_query_result_digest(&result).expect("digest must verify"));
    }
    let elapsed = started.elapsed();
    let result_bytes = serde_json::to_vec(&first)
        .expect("baseline result must encode")
        .len();
    println!(
        "QUERY_BASELINE iterations=1000 elapsed_microseconds={} serialized_result_bytes={} serialized_package_bytes={} signed_source_bytes={}",
        elapsed.as_micros(),
        result_bytes,
        metrics.serialized_package_bytes,
        metrics.signed_source_bytes
    );
    assert!(
        elapsed.as_secs() < 10,
        "fixture baseline must remain bounded enough for local deterministic use"
    );
}
