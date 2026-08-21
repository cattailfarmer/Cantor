use std::collections::{BTreeMap, BTreeSet};

mod common;

use cantor_core::{
    ANCHOR_QUERY_PROFILE, ANCHOR_QUERY_RESULT_PROFILE, AnchorBudget, AnchorCandidate,
    AnchorDerivationFaultKind, AnchorFormFaultKind, AnchorLifecycle, AnchorProof, AnchorQuery,
    AnchorQueryResult, AnchorRelationshipPath, AnchorRelationshipStep, ApplicabilityBinding,
    ApplicabilityStatus, AssociationChannel, AssociationContribution, AuthorityContext,
    AuthorityScope, BoundaryAccount, CandidateEligibility, CatalogueDerivationRequest,
    CatalogueIdentity, ChannelLocalValue, ContentDigest, ContributionStatus,
    DERIVED_LEXICAL_ASSOCIATION_INDEX_PROFILE, DerivedLexicalAssociationIndex,
    DerivedSemanticAnchorCatalogue, IdentityAnchorEntry, LEXICAL_ANCHOR_LOOKUP_NON_AUTHORITY,
    LEXICAL_ANCHOR_LOOKUP_PROFILE, LEXICAL_ASSOCIATION_INDEX_COMPILER_ID,
    LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION, LEXICAL_TOKENIZER_PROFILE,
    LEXICALLY_SEEDED_ANCHOR_GATE_NON_AUTHORITY, LEXICALLY_SEEDED_ANCHOR_GATE_PROFILE,
    LexicalAnchorLookupBudget, LexicalAnchorLookupRequest, LexicalAnchorSourceProjectionBudget,
    LexicalAnchorSourceProjectionResult, LexicalIndexDerivationRequest, LexicalIndexFaultKind,
    LexicalLookupFaultKind, LexicalPosting, LexicalSourceProjectionFaultKind, LexicalSurfaceKind,
    LexicalTokenizerIdentity, LexicallySeededAnchorGateBudget, LexicallySeededAnchorGateFaultKind,
    LexicallySeededAnchorGateRequest, MAX_LEXICAL_SURFACE_BYTES, OperationAnchorEntry,
    OperationClass, OperationRole, PriorityTier, RelationType, RelationshipDirection,
    RequestedDetailKind, SEMANTIC_ANCHOR_CATALOGUE_PROFILE, SemanticAddress,
    SemanticAnchorCatalogue, SemanticFabric, SemanticId, SourceAnchor, UnitKind, UnitStatus,
    admit_package, anchor_query_result_digest, candidate_association_account,
    candidate_relationship_paths, catalogue_derivation_digest, catalogue_root,
    derive_lexical_association_index, derive_semantic_anchor_catalogue,
    derived_semantic_anchor_catalogue_digest, gate_lexical_anchor_matches,
    lexical_anchor_lookup_proof_digest, lexical_anchor_source_projection_digest,
    lexical_anchor_source_projection_result_digest, lexical_association_index_proof_digest,
    lexical_association_index_root, lexical_tokenizer_adversarial_fixture_digest,
    lexically_seeded_anchor_gate_result_digest, lookup_lexical_anchors,
    project_lexical_anchor_sources, tokenize_lexical_surface, validate_anchor_candidate,
    validate_anchor_query, validate_anchor_query_result,
    validate_derived_lexical_association_index, validate_derived_lexical_association_index_form,
    validate_derived_semantic_anchor_catalogue, validate_lexical_anchor_lookup_request,
    validate_lexical_anchor_lookup_result, validate_lexical_anchor_lookup_result_form,
    validate_lexical_anchor_source_projection_result,
    validate_lexical_anchor_source_projection_result_form,
    validate_lexical_index_derivation_request, validate_lexically_seeded_anchor_gate_request,
    validate_lexically_seeded_anchor_gate_result,
    validate_lexically_seeded_anchor_gate_result_form, validate_semantic_anchor_catalogue,
};

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture id")
}

fn digest(byte: char) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: byte.to_string().repeat(64),
    }
}

fn derivation_request() -> CatalogueDerivationRequest {
    CatalogueDerivationRequest {
        catalogue_id: id("catalogue:derived_fixture"),
        logical_revision: "fixture-generation-r1".to_owned(),
    }
}

fn fabric_from_inputs(
    inputs: Vec<cantor_core::PackageCompilationInput>,
    authority_scope: AuthorityScope,
) -> SemanticFabric {
    let compiler = common::compiler("1.0.0");
    let store = common::trust_store(&compiler, "1.0.0", &authority_scope);
    let admitted = inputs
        .into_iter()
        .map(|mut input| {
            input.authority_scope = authority_scope.clone();
            let package = compiler.compile(input).expect("fixture package compiles");
            admit_package(&package, &store, &authority_scope, common::NOW)
                .expect("fixture package admits")
        })
        .collect::<Vec<_>>();
    SemanticFabric::from_admitted(admitted).expect("fixture fabric loads")
}

fn fixture_fabric() -> SemanticFabric {
    fabric_from_inputs(vec![common::package_input("")], common::scope())
}

fn renamed_package_input(suffix: &str) -> cantor_core::PackageCompilationInput {
    let mut input = common::package_input("");
    let mut file_ids = BTreeMap::new();
    for source in &mut input.sources {
        let renamed = id(&format!("{}:{suffix}", source.file_id.as_str()));
        file_ids.insert(source.file_id.clone(), renamed.clone());
        source.file_id = renamed;
        source.path = format!("fixtures/{suffix}/{}", source.path);
    }
    let mut unit_ids = BTreeMap::new();
    for compilation in &mut input.units {
        let renamed = id(&format!("{}:{suffix}", compilation.unit.unit_id.as_str()));
        unit_ids.insert(compilation.unit.unit_id.clone(), renamed.clone());
        compilation.unit.unit_id = renamed;
        compilation.file_id = file_ids
            .get(&compilation.file_id)
            .expect("source identity remaps")
            .clone();
        compilation.clause_id = id(&format!("{}:{suffix}", compilation.clause_id.as_str()));
    }
    for relation in &mut input.relations {
        relation.relation_id = id(&format!("{}:{suffix}", relation.relation_id.as_str()));
        relation.source = unit_ids
            .get(&relation.source)
            .expect("relation source remaps")
            .clone();
        relation.target = unit_ids
            .get(&relation.target)
            .expect("relation target remaps")
            .clone();
        relation.source_ref = format!("fixture:{suffix}");
    }
    input
}

fn derive_fixture(fabric: &SemanticFabric) -> DerivedSemanticAnchorCatalogue {
    derive_semantic_anchor_catalogue(fabric, derivation_request())
        .expect("fixture catalogue derives")
}

fn lexical_index_form() -> DerivedLexicalAssociationIndex {
    let posting = LexicalPosting {
        token: "anchor".to_owned(),
        address: address("unit:anchor", UnitKind::Declaration, 'c'),
        surface_kind: LexicalSurfaceKind::PreferredExpression,
        surface_digest: digest('d'),
        occurrence_count: 1,
        evidence_refs: BTreeSet::from([id("evidence:anchor")]),
    };
    let mut index = DerivedLexicalAssociationIndex {
        profile: DERIVED_LEXICAL_ASSOCIATION_INDEX_PROFILE.to_owned(),
        index_id: id("lexical-index:fixture"),
        logical_revision: "fixture-r1".to_owned(),
        catalogue_root: digest('e'),
        fabric_root: digest('f'),
        compiler_id: id(LEXICAL_ASSOCIATION_INDEX_COMPILER_ID),
        compiler_version: LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION.to_owned(),
        tokenizer: LexicalTokenizerIdentity {
            profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
            compiler_id: id(LEXICAL_ASSOCIATION_INDEX_COMPILER_ID),
            compiler_version: LEXICAL_ASSOCIATION_INDEX_COMPILER_VERSION.to_owned(),
            adversarial_fixture_digest: lexical_tokenizer_adversarial_fixture_digest()
                .expect("lexical fixture digest"),
        },
        postings: BTreeMap::from([("anchor".to_owned(), vec![posting])]),
        index_root: digest('1'),
        proof_digest: digest('2'),
    };
    index.index_root = lexical_association_index_root(&index).expect("lexical fixture root");
    index
}

fn lexical_derivation_request() -> LexicalIndexDerivationRequest {
    LexicalIndexDerivationRequest {
        index_id: id("lexical-index:derived_fixture"),
        logical_revision: "fixture-lexical-r1".to_owned(),
        tokenizer_profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
    }
}

fn lexical_lookup_request(terms: &[&str]) -> LexicalAnchorLookupRequest {
    LexicalAnchorLookupRequest {
        profile: LEXICAL_ANCHOR_LOOKUP_PROFILE.to_owned(),
        request_id: id("request:lexical_lookup_fixture"),
        terms: terms.iter().map(|term| (*term).to_owned()).collect(),
        budget: LexicalAnchorLookupBudget {
            maximum_terms: 16,
            maximum_query_bytes: 16_384,
            maximum_unique_tokens: 256,
            maximum_postings: 4_096,
            maximum_matches: 256,
            maximum_serialized_result_bytes: 4 * 1024 * 1024,
        },
    }
}

fn lexical_gate_request(
    lexical_result: &cantor_core::LexicalAnchorLookupResult,
) -> LexicallySeededAnchorGateRequest {
    LexicallySeededAnchorGateRequest {
        profile: LEXICALLY_SEEDED_ANCHOR_GATE_PROFILE.to_owned(),
        request_id: id("request:lexically_seeded_gate_fixture"),
        scanner_query: AnchorQuery {
            profile: ANCHOR_QUERY_PROFILE.to_owned(),
            request_id: id("request:lexically_seeded_gate_fixture"),
            term_set: BTreeSet::new(),
            subject: Some("lexically proposed semantic anchors".to_owned()),
            purpose: "trusted-package fixture".to_owned(),
            use_cases: BTreeSet::new(),
            include_boundaries: BTreeSet::new(),
            exclude_boundaries: BTreeSet::new(),
            known_identities: lexical_result
                .matches
                .iter()
                .map(|matched| matched.address.unit_id.clone())
                .collect(),
            requested_details: BTreeSet::new(),
            allowed_relations: BTreeSet::new(),
            allowed_channels: BTreeSet::from([AssociationChannel::ExactIdentity]),
            authority_context: AuthorityContext {
                caller_id: id("caller:lexically_seeded_gate_fixture"),
                allowed_package_scopes: BTreeSet::from(["cantor".to_owned()]),
                operation: "read".to_owned(),
                effect_boundary: "read_only".to_owned(),
            },
            budget: AnchorBudget {
                maximum_candidates: 16,
                maximum_records: 16,
                maximum_paths: 1,
                maximum_depth: 1,
                maximum_bytes: 128 * 1024,
                maximum_elapsed_milliseconds: 1_000,
                maximum_continuations: 0,
            },
        },
        budget: LexicallySeededAnchorGateBudget {
            maximum_lexical_matches: 16,
            maximum_scanner_candidates: 16,
            maximum_serialized_result_bytes: 4 * 1024 * 1024,
        },
    }
}

fn lexical_source_projection_budget() -> LexicalAnchorSourceProjectionBudget {
    LexicalAnchorSourceProjectionBudget {
        maximum_projections: 256,
        maximum_quote_bytes: 4 * 1024 * 1024,
        maximum_serialized_result_bytes: 8 * 1024 * 1024,
    }
}

fn reseal_lexical_index(
    index: &mut DerivedLexicalAssociationIndex,
    request: &LexicalIndexDerivationRequest,
    catalogue: &DerivedSemanticAnchorCatalogue,
) {
    index.index_root = lexical_association_index_root(index).expect("resealed lexical root");
    index.proof_digest = lexical_association_index_proof_digest(index, request, catalogue)
        .expect("resealed lexical proof");
}

fn reseal_derived_catalogue(derived: &mut DerivedSemanticAnchorCatalogue) {
    derived.catalogue.identity.derivation_digest =
        catalogue_derivation_digest(&derived.catalogue.identity)
            .expect("resealed catalogue derivation");
    derived.catalogue.identity.catalogue_root =
        catalogue_root(&derived.catalogue).expect("resealed catalogue root");
    derived.proof_digest =
        derived_semantic_anchor_catalogue_digest(derived).expect("resealed catalogue proof");
}

fn address(unit: &str, kind: UnitKind, byte: char) -> SemanticAddress {
    let unit_id = id(unit);
    let package_id = id("package:fixture");
    SemanticAddress {
        unit_id: unit_id.clone(),
        unit_digest: digest(byte),
        package_id: package_id.clone(),
        package_digest: digest('a'),
        kind,
        context_id: id("context:fixture"),
        version: "0.1".to_owned(),
        source_anchors: vec![SourceAnchor {
            package_id,
            file_id: id("file:fixture"),
            unit_id,
            clause_id: id("clause:fixture"),
            byte_start: 1,
            byte_end: 10,
            span_digest: digest('b'),
            display_line_start: 1,
            display_line_end: 1,
        }],
    }
}

fn fixture_catalogue() -> SemanticAnchorCatalogue {
    let identity_address = address("unit:anchor", UnitKind::Declaration, 'c');
    let operation_address = address("unit:observe", UnitKind::Operation, 'd');
    let mut catalogue = SemanticAnchorCatalogue {
        identity: CatalogueIdentity {
            profile: SEMANTIC_ANCHOR_CATALOGUE_PROFILE.to_owned(),
            catalogue_id: id("catalogue:fixture"),
            logical_revision: "fixture-r1".to_owned(),
            catalogue_root: digest('0'),
            fabric_root: digest('e'),
            package_roots: BTreeMap::from([(id("package:fixture"), digest('a'))]),
            compiler_id: id("compiler:fixture"),
            compiler_version: "0.1".to_owned(),
            derivation_digest: digest('0'),
        },
        identity_entries: vec![IdentityAnchorEntry {
            address: identity_address.clone(),
            preferred_expression: "anchor".to_owned(),
            aliases: BTreeSet::from(["semantic anchor".to_owned()]),
            meaning_ref: id("unit:anchor-meaning"),
            purposes: BTreeSet::from(["focus meaning".to_owned()]),
            use_cases: BTreeSet::from(["attention loading".to_owned()]),
            included_boundaries: BTreeSet::from(["signed records".to_owned()]),
            excluded_boundaries: BTreeSet::from(["unverified text".to_owned()]),
            protected_identities: BTreeSet::new(),
            relation_refs: BTreeSet::from([id("relation:observe-anchor")]),
            lifecycle: AnchorLifecycle::Admitted,
        }],
        operation_entries: vec![OperationAnchorEntry {
            address: operation_address,
            operation_class: OperationClass::Observation,
            verbs: BTreeSet::from(["observe".to_owned()]),
            aliases: BTreeSet::new(),
            roles: vec![OperationRole {
                name: "subject".to_owned(),
                required: true,
                accepted_kinds: vec![UnitKind::Declaration],
            }],
            preconditions: BTreeSet::from(["subject admitted".to_owned()]),
            invariants: BTreeSet::from(["identity preserved".to_owned()]),
            postconditions: BTreeSet::from(["observation proposed".to_owned()]),
            failure_conditions: BTreeSet::from(["source unavailable".to_owned()]),
            authority_requirements: BTreeSet::from(["read".to_owned()]),
            effect_class: "none".to_owned(),
            non_transfer_set: BTreeSet::from(["authority".to_owned()]),
            applicability_refs: BTreeSet::from([id("binding:observe-anchor")]),
            lifecycle: AnchorLifecycle::Admitted,
        }],
        applicability_bindings: vec![ApplicabilityBinding {
            binding_id: id("binding:observe-anchor"),
            operation_ref: id("unit:observe"),
            role_ref: "subject".to_owned(),
            identity_ref: Some(identity_address.unit_id),
            admitted_kind: None,
            context: "fixture".to_owned(),
            purpose: "focus meaning".to_owned(),
            conditions: BTreeSet::from(["subject admitted".to_owned()]),
            boundary_refs: BTreeSet::new(),
            evidence_refs: BTreeSet::from([id("evidence:fixture")]),
            transfer_law: "preserve identity".to_owned(),
            non_transfer_set: BTreeSet::from(["authority".to_owned()]),
            authority_ref: None,
            status: ApplicabilityStatus::Declared,
        }],
    };
    catalogue.identity.derivation_digest =
        catalogue_derivation_digest(&catalogue.identity).expect("derivation");
    catalogue.identity.catalogue_root = catalogue_root(&catalogue).expect("root");
    catalogue
}

fn fixture_query() -> AnchorQuery {
    AnchorQuery {
        profile: ANCHOR_QUERY_PROFILE.to_owned(),
        request_id: id("request:fixture"),
        term_set: BTreeSet::from(["anchor".to_owned()]),
        subject: Some("semantic catalogue".to_owned()),
        purpose: "focus meaning".to_owned(),
        use_cases: BTreeSet::from(["attention loading".to_owned()]),
        include_boundaries: BTreeSet::from(["signed records".to_owned()]),
        exclude_boundaries: BTreeSet::from(["unverified text".to_owned()]),
        known_identities: BTreeSet::new(),
        requested_details: BTreeSet::from([RequestedDetailKind::Definition]),
        allowed_relations: BTreeSet::from([RelationType::Supports]),
        allowed_channels: BTreeSet::from([
            AssociationChannel::ExactLabel,
            AssociationChannel::Lexical,
        ]),
        authority_context: AuthorityContext {
            caller_id: id("caller:fixture"),
            allowed_package_scopes: BTreeSet::from(["fixture".to_owned()]),
            operation: "read".to_owned(),
            effect_boundary: "none".to_owned(),
        },
        budget: AnchorBudget {
            maximum_candidates: 8,
            maximum_records: 8,
            maximum_paths: 8,
            maximum_depth: 2,
            maximum_bytes: 65_536,
            maximum_elapsed_milliseconds: 1_000,
            maximum_continuations: 1,
        },
    }
}

fn contribution(address: &SemanticAddress, channel: AssociationChannel) -> AssociationContribution {
    let channel_local_value = match channel {
        AssociationChannel::ExactIdentity | AssociationChannel::ExactLabel => {
            ChannelLocalValue::Exact
        }
        AssociationChannel::DeclaredApplicability => ChannelLocalValue::Declared,
        AssociationChannel::TypedRelation => ChannelLocalValue::RelationHops(1),
        AssociationChannel::Lexical | AssociationChannel::Embedding => {
            ChannelLocalValue::RelevanceBasisPoints(7500)
        }
        AssociationChannel::LearnedRoute => ChannelLocalValue::LearnedBasisPoints {
            basis_points: 7500,
            model_digest: digest('f'),
        },
    };
    let relation_id = id("relation:fixture_contribution");
    let relationship_path =
        (channel == AssociationChannel::TypedRelation).then(|| AnchorRelationshipPath {
            seed_id: id("unit:fixture_seed"),
            target_id: address.unit_id.clone(),
            steps: vec![AnchorRelationshipStep {
                relation_id: relation_id.clone(),
                relation_type: RelationType::Supports,
                relation_source: id("unit:fixture_seed"),
                relation_target: address.unit_id.clone(),
                direction: RelationshipDirection::Forward,
            }],
        });
    AssociationContribution {
        channel,
        candidate_address: address.clone(),
        basis: "fixture basis".to_owned(),
        channel_local_value,
        evidence_refs: relationship_path
            .as_ref()
            .map(|_| BTreeSet::from([relation_id]))
            .unwrap_or_default(),
        conditions: BTreeSet::new(),
        unresolved_guards: BTreeSet::new(),
        relationship_path,
        status: ContributionStatus::Retained,
    }
}

fn candidate(address: SemanticAddress) -> AnchorCandidate {
    AnchorCandidate {
        address: address.clone(),
        contributions: vec![contribution(&address, AssociationChannel::ExactLabel)],
        priority_tier: PriorityTier::ExactLabel,
        channel_local_rank: 1,
        eligibility: CandidateEligibility::Ambiguous,
        unresolved_guards: BTreeSet::new(),
        exact_resolution_required: true,
    }
}

fn fixture_result() -> AnchorQueryResult {
    let catalogue = fixture_catalogue();
    let candidate = candidate(catalogue.identity_entries[0].address.clone());
    let unit_id = candidate.address.unit_id.clone();
    let source_anchors = candidate.address.source_anchors.clone();
    let candidates = vec![candidate];
    let relationship_paths = candidate_relationship_paths(&candidates).expect("paths");
    let association_account = candidate_association_account(&candidates).expect("account");
    let mut result = AnchorQueryResult {
        profile: ANCHOR_QUERY_RESULT_PROFILE.to_owned(),
        request_id: id("request:fixture"),
        catalogue_root: catalogue.identity.catalogue_root.clone(),
        fabric_root: catalogue.identity.fabric_root.clone(),
        candidates,
        record_ids: vec![unit_id.clone()],
        relationship_paths,
        association_account,
        source_anchors,
        boundary_account: BoundaryAccount {
            admitted: Vec::new(),
            excluded: Vec::new(),
            ambiguous: vec![unit_id],
            contradictory: Vec::new(),
            unknown: Vec::new(),
            stale: Vec::new(),
            unauthorized: Vec::new(),
            budget_clipped: false,
        },
        proof: AnchorProof {
            catalogue_root: catalogue.identity.catalogue_root,
            fabric_root: catalogue.identity.fabric_root,
            input_digest: digest('1'),
            decisions: vec!["exact label retained".to_owned()],
            omissions: Vec::new(),
        },
        continuation: None,
        result_digest: digest('0'),
    };
    result.result_digest = anchor_query_result_digest(&result).expect("result digest");
    result
}

#[test]
fn catalogue_fixture_is_closed_deterministic_and_root_bound() {
    let catalogue = fixture_catalogue();
    validate_semantic_anchor_catalogue(&catalogue).expect("valid catalogue");
    assert_eq!(
        catalogue_root(&catalogue).expect("root"),
        catalogue.identity.catalogue_root
    );
    assert_eq!(
        serde_json::to_vec(&catalogue).expect("first"),
        serde_json::to_vec(&fixture_catalogue()).expect("second")
    );
}

#[test]
fn catalogue_root_and_order_mutations_fail_closed() {
    let mut wrong_root = fixture_catalogue();
    wrong_root
        .identity
        .catalogue_root
        .value
        .replace_range(0..1, "9");
    assert_eq!(
        validate_semantic_anchor_catalogue(&wrong_root)
            .expect_err("root")
            .kind,
        AnchorFormFaultKind::InvalidDigest
    );
    let mut duplicate = fixture_catalogue();
    duplicate
        .identity_entries
        .push(duplicate.identity_entries[0].clone());
    assert_eq!(
        validate_semantic_anchor_catalogue(&duplicate)
            .expect_err("duplicate")
            .kind,
        AnchorFormFaultKind::NonCanonicalOrder
    );
}

#[test]
fn query_bounds_and_unknown_fields_fail_closed() {
    let query = fixture_query();
    validate_anchor_query(&query).expect("valid query");
    let mut oversized = query.clone();
    oversized.budget.maximum_candidates = 1025;
    assert_eq!(
        validate_anchor_query(&oversized).expect_err("bound").kind,
        AnchorFormFaultKind::InvalidBound
    );
    let mut value = serde_json::to_value(query).expect("value");
    value
        .as_object_mut()
        .expect("object")
        .insert("authority_score".to_owned(), serde_json::json!(100));
    assert!(serde_json::from_value::<AnchorQuery>(value).is_err());
}

#[test]
fn every_association_channel_accepts_only_its_local_value_shape() {
    let address = fixture_catalogue().identity_entries[0].address.clone();
    for channel in [
        AssociationChannel::ExactIdentity,
        AssociationChannel::ExactLabel,
        AssociationChannel::DeclaredApplicability,
        AssociationChannel::TypedRelation,
        AssociationChannel::Lexical,
        AssociationChannel::Embedding,
        AssociationChannel::LearnedRoute,
    ] {
        let tier = match channel {
            AssociationChannel::ExactIdentity => PriorityTier::ExactIdentity,
            AssociationChannel::ExactLabel => PriorityTier::ExactLabel,
            AssociationChannel::DeclaredApplicability => PriorityTier::DeclaredApplicability,
            AssociationChannel::TypedRelation => PriorityTier::TypedRelation,
            AssociationChannel::Lexical => PriorityTier::Lexical,
            AssociationChannel::Embedding => PriorityTier::Embedding,
            AssociationChannel::LearnedRoute => PriorityTier::LearnedRoute,
        };
        let candidate = AnchorCandidate {
            address: address.clone(),
            contributions: vec![contribution(&address, channel)],
            priority_tier: tier,
            channel_local_rank: 1,
            eligibility: CandidateEligibility::Eligible,
            unresolved_guards: BTreeSet::new(),
            exact_resolution_required: true,
        };
        validate_anchor_candidate(&candidate).expect("compatible channel");
    }
    let mut wrong = candidate(address.clone());
    wrong.contributions[0].channel_local_value = ChannelLocalValue::RelevanceBasisPoints(9000);
    assert_eq!(
        validate_anchor_candidate(&wrong)
            .expect_err("mismatch")
            .kind,
        AnchorFormFaultKind::ChannelValueMismatch
    );
}

#[test]
fn priority_lattice_and_exact_resolution_are_mandatory() {
    let address = fixture_catalogue().identity_entries[0].address.clone();
    let mut wrong_tier = candidate(address.clone());
    wrong_tier
        .contributions
        .push(contribution(&address, AssociationChannel::Lexical));
    wrong_tier.priority_tier = PriorityTier::Lexical;
    assert_eq!(
        validate_anchor_candidate(&wrong_tier)
            .expect_err("tier")
            .kind,
        AnchorFormFaultKind::PriorityMismatch
    );
    let mut unresolved = candidate(address);
    unresolved.exact_resolution_required = false;
    assert_eq!(
        validate_anchor_candidate(&unresolved)
            .expect_err("resolution")
            .kind,
        AnchorFormFaultKind::ExactResolutionDisabled
    );
}

#[test]
fn typed_relationship_paths_bind_channel_hops_direction_target_and_evidence() {
    let address = fixture_catalogue().identity_entries[0].address.clone();
    let typed = contribution(&address, AssociationChannel::TypedRelation);
    let typed_candidate = AnchorCandidate {
        address: address.clone(),
        contributions: vec![typed.clone()],
        priority_tier: PriorityTier::TypedRelation,
        channel_local_rank: 1,
        eligibility: CandidateEligibility::Eligible,
        unresolved_guards: BTreeSet::new(),
        exact_resolution_required: true,
    };
    validate_anchor_candidate(&typed_candidate).expect("typed path is valid");

    let mut missing = typed_candidate.clone();
    missing.contributions[0].relationship_path = None;
    assert_eq!(
        validate_anchor_candidate(&missing)
            .expect_err("typed path required")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut wrong_direction = typed_candidate.clone();
    wrong_direction.contributions[0]
        .relationship_path
        .as_mut()
        .expect("path")
        .steps[0]
        .direction = RelationshipDirection::Reverse;
    assert_eq!(
        validate_anchor_candidate(&wrong_direction)
            .expect_err("direction")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut wrong_seed = typed_candidate.clone();
    wrong_seed.contributions[0]
        .relationship_path
        .as_mut()
        .expect("path")
        .seed_id = id("unit:wrong_seed");
    assert_eq!(
        validate_anchor_candidate(&wrong_seed)
            .expect_err("seed must begin the first step")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut wrong_target = typed_candidate.clone();
    wrong_target.contributions[0]
        .relationship_path
        .as_mut()
        .expect("path")
        .target_id = id("unit:wrong_target");
    assert_eq!(
        validate_anchor_candidate(&wrong_target)
            .expect_err("target must equal candidate")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut discontinuous = typed_candidate.clone();
    discontinuous.contributions[0]
        .relationship_path
        .as_mut()
        .expect("path")
        .steps[0]
        .relation_source = id("unit:unrelated");
    assert_eq!(
        validate_anchor_candidate(&discontinuous)
            .expect_err("path must remain continuous")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut wrong_hops = typed_candidate.clone();
    wrong_hops.contributions[0].channel_local_value = ChannelLocalValue::RelationHops(2);
    assert_eq!(
        validate_anchor_candidate(&wrong_hops)
            .expect_err("hops")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut missing_evidence = typed_candidate.clone();
    missing_evidence.contributions[0].evidence_refs.clear();
    assert_eq!(
        validate_anchor_candidate(&missing_evidence)
            .expect_err("evidence")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut wrong_channel = candidate(address);
    wrong_channel.contributions[0].relationship_path = typed.relationship_path.clone();
    assert_eq!(
        validate_anchor_candidate(&wrong_channel)
            .expect_err("path channel")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut duplicate = typed_candidate;
    duplicate.contributions.push(typed);
    assert_eq!(
        candidate_relationship_paths(std::slice::from_ref(&duplicate))
            .expect_err("duplicate path")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );
}

#[test]
fn result_paths_and_association_account_exactly_recompute_from_candidates() {
    let mut result = fixture_result();
    let result_address = result.candidates[0].address.clone();
    result.candidates[0]
        .contributions
        .push(contribution(&result_address, AssociationChannel::Lexical));
    result.relationship_paths = candidate_relationship_paths(&result.candidates).expect("paths");
    result.association_account =
        candidate_association_account(&result.candidates).expect("account");
    result.result_digest = anchor_query_result_digest(&result).expect("digest");
    validate_anchor_query_result(&result).expect("accounted result");
    assert_eq!(result.association_account.len(), 2);

    let mut wrong_count = result.clone();
    wrong_count.association_account[0].contribution_count += 1;
    wrong_count.result_digest = anchor_query_result_digest(&wrong_count).expect("mutated digest");
    assert_eq!(
        validate_anchor_query_result(&wrong_count)
            .expect_err("count")
            .kind,
        AnchorFormFaultKind::AssociationAccountMismatch
    );

    let mut wrong_order = result.clone();
    wrong_order.association_account.reverse();
    wrong_order.result_digest = anchor_query_result_digest(&wrong_order).expect("mutated digest");
    assert_eq!(
        validate_anchor_query_result(&wrong_order)
            .expect_err("account order")
            .kind,
        AnchorFormFaultKind::AssociationAccountMismatch
    );

    let mut omitted_account = result.clone();
    omitted_account.association_account.clear();
    omitted_account.result_digest =
        anchor_query_result_digest(&omitted_account).expect("mutated digest");
    assert_eq!(
        validate_anchor_query_result(&omitted_account)
            .expect_err("account omission")
            .kind,
        AnchorFormFaultKind::AssociationAccountMismatch
    );

    let mut extra_account = result.clone();
    extra_account
        .association_account
        .push(extra_account.association_account[0].clone());
    extra_account.result_digest =
        anchor_query_result_digest(&extra_account).expect("mutated digest");
    assert_eq!(
        validate_anchor_query_result(&extra_account)
            .expect_err("account addition")
            .kind,
        AnchorFormFaultKind::AssociationAccountMismatch
    );

    let address = result.candidates[0].address.clone();
    let typed = AnchorCandidate {
        address: address.clone(),
        contributions: vec![contribution(&address, AssociationChannel::TypedRelation)],
        priority_tier: PriorityTier::TypedRelation,
        channel_local_rank: 1,
        eligibility: CandidateEligibility::Eligible,
        unresolved_guards: BTreeSet::new(),
        exact_resolution_required: true,
    };
    let mut typed_result = result;
    typed_result.candidates = vec![typed];
    typed_result.record_ids = vec![address.unit_id.clone()];
    typed_result.relationship_paths =
        candidate_relationship_paths(&typed_result.candidates).expect("typed paths");
    typed_result.association_account =
        candidate_association_account(&typed_result.candidates).expect("typed account");
    typed_result.boundary_account = BoundaryAccount {
        admitted: vec![address.unit_id.clone()],
        excluded: Vec::new(),
        ambiguous: Vec::new(),
        contradictory: Vec::new(),
        unknown: Vec::new(),
        stale: Vec::new(),
        unauthorized: Vec::new(),
        budget_clipped: false,
    };
    typed_result.result_digest = anchor_query_result_digest(&typed_result).expect("typed digest");
    validate_anchor_query_result(&typed_result).expect("typed result");
    typed_result.relationship_paths.clear();
    typed_result.result_digest = anchor_query_result_digest(&typed_result).expect("mutated digest");
    assert_eq!(
        validate_anchor_query_result(&typed_result)
            .expect_err("path omission")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );

    let mut extra_path = fixture_result();
    extra_path.relationship_paths.push(
        candidate_relationship_paths(&[AnchorCandidate {
            address: address.clone(),
            contributions: vec![contribution(&address, AssociationChannel::TypedRelation)],
            priority_tier: PriorityTier::TypedRelation,
            channel_local_rank: 1,
            eligibility: CandidateEligibility::Eligible,
            unresolved_guards: BTreeSet::new(),
            exact_resolution_required: true,
        }])
        .expect("fixture typed path")
        .remove(0),
    );
    extra_path.result_digest = anchor_query_result_digest(&extra_path).expect("mutated digest");
    assert_eq!(
        validate_anchor_query_result(&extra_path)
            .expect_err("extra path")
            .kind,
        AnchorFormFaultKind::RelationshipPathMismatch
    );
}

#[test]
fn result_fixture_preserves_ambiguity_roots_and_digest() {
    let result = fixture_result();
    validate_anchor_query_result(&result).expect("valid result");
    assert_eq!(
        serde_json::to_vec(&result).expect("first"),
        serde_json::to_vec(&fixture_result()).expect("second")
    );
    let mut missing_ambiguity = result.clone();
    missing_ambiguity.boundary_account.ambiguous.clear();
    assert!(validate_anchor_query_result(&missing_ambiguity).is_err());
    let mut wrong_root = result.clone();
    wrong_root.proof.fabric_root = digest('8');
    assert_eq!(
        validate_anchor_query_result(&wrong_root)
            .expect_err("root")
            .kind,
        AnchorFormFaultKind::RootMismatch
    );
    let mut wrong_digest = result;
    wrong_digest.result_digest.value.replace_range(0..1, "7");
    assert_eq!(
        validate_anchor_query_result(&wrong_digest)
            .expect_err("digest")
            .kind,
        AnchorFormFaultKind::ResultDigestMismatch
    );
}

#[test]
fn source_anchor_and_applicability_target_boundaries_fail_closed() {
    let mut bad_anchor = fixture_catalogue();
    bad_anchor.identity_entries[0].address.source_anchors[0].unit_id = id("unit:other");
    assert_eq!(
        validate_semantic_anchor_catalogue(&bad_anchor)
            .expect_err("anchor")
            .kind,
        AnchorFormFaultKind::InvalidIdentity
    );
    let mut two_targets = fixture_catalogue();
    two_targets.applicability_bindings[0].admitted_kind = Some(UnitKind::Declaration);
    assert_eq!(
        validate_semantic_anchor_catalogue(&two_targets)
            .expect_err("target")
            .kind,
        AnchorFormFaultKind::InvalidIdentity
    );
}

#[test]
fn package_operation_and_binding_references_are_closed_over_the_catalogue() {
    let mut wrong_package = fixture_catalogue();
    wrong_package.identity_entries[0].address.package_digest = digest('9');
    assert_eq!(
        validate_semantic_anchor_catalogue(&wrong_package)
            .expect_err("package root")
            .kind,
        AnchorFormFaultKind::RootMismatch
    );

    let mut wrong_kind = fixture_catalogue();
    wrong_kind.operation_entries[0].address.kind = UnitKind::Program;
    assert_eq!(
        validate_semantic_anchor_catalogue(&wrong_kind)
            .expect_err("operation kind")
            .kind,
        AnchorFormFaultKind::InvalidIdentity
    );

    let mut missing_binding = fixture_catalogue();
    missing_binding.operation_entries[0]
        .applicability_refs
        .insert(id("binding:absent"));
    assert_eq!(
        validate_semantic_anchor_catalogue(&missing_binding)
            .expect_err("binding closure")
            .kind,
        AnchorFormFaultKind::InvalidIdentity
    );
}

#[test]
fn duplicate_result_candidates_and_records_are_not_canonical() {
    let mut duplicate_candidate = fixture_result();
    duplicate_candidate
        .candidates
        .push(duplicate_candidate.candidates[0].clone());
    duplicate_candidate.result_digest =
        anchor_query_result_digest(&duplicate_candidate).expect("digest");
    assert_eq!(
        validate_anchor_query_result(&duplicate_candidate)
            .expect_err("candidate order")
            .kind,
        AnchorFormFaultKind::NonCanonicalOrder
    );

    let mut duplicate_record = fixture_result();
    duplicate_record
        .record_ids
        .push(duplicate_record.record_ids[0].clone());
    duplicate_record.result_digest = anchor_query_result_digest(&duplicate_record).expect("digest");
    assert_eq!(
        validate_anchor_query_result(&duplicate_record)
            .expect_err("record order")
            .kind,
        AnchorFormFaultKind::NonCanonicalOrder
    );
}

#[test]
fn admitted_fabric_derives_exact_identity_index_adjacency_and_source_proof() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);

    validate_derived_semantic_anchor_catalogue(&derived, &fabric).expect("canonical rebuild");
    assert_eq!(derived.generation.packages.len(), 1);
    assert_eq!(derived.catalogue.identity_entries.len(), 2);
    assert!(derived.catalogue.operation_entries.is_empty());
    assert!(derived.catalogue.applicability_bindings.is_empty());
    assert!(derived.omissions.is_empty());
    assert_eq!(
        derived
            .exact_label_index
            .get("bank")
            .expect("shared exact label")
            .len(),
        2
    );
    let relation_id = id("relation:bank_meanings_distinct");
    for unit_id in [id("unit:bank_financial"), id("unit:bank_river")] {
        let unit = fabric.unit(&unit_id).expect("exact source unit");
        let package = fabric
            .package_for_unit(&unit_id)
            .expect("exact source package");
        let certificate = package
            .package()
            .certificate
            .as_ref()
            .expect("admitted certificate");
        let entry = derived
            .catalogue
            .identity_entries
            .iter()
            .find(|entry| entry.address.unit_id == unit_id)
            .expect("derived identity entry");
        assert_eq!(entry.preferred_expression, unit.expression);
        assert_eq!(entry.aliases, unit.aliases);
        assert_eq!(entry.address.kind, unit.kind);
        assert_eq!(entry.address.package_id, package.package().package_id);
        assert_eq!(entry.address.package_digest, certificate.package_digest);
        assert_eq!(
            entry.address.source_anchors,
            package
                .content()
                .source_anchors
                .iter()
                .filter(|anchor| anchor.unit_id == unit_id)
                .cloned()
                .collect::<Vec<_>>()
        );
        assert!(entry.meaning_ref.as_str().starts_with("meaning:sha256:"));
        assert!(
            entry
                .address
                .context_id
                .as_str()
                .starts_with("context:sha256:")
        );
        assert!(entry.relation_refs.contains(&relation_id));
        assert!(
            derived
                .relation_adjacency
                .get(&unit_id)
                .expect("relation adjacency")
                .contains(&relation_id)
        );
    }
}

#[test]
fn admitted_package_input_order_does_not_change_derived_bytes() {
    let first = renamed_package_input("first");
    let second = renamed_package_input("second");
    let forward = fabric_from_inputs(vec![first.clone(), second.clone()], common::scope());
    let reverse = fabric_from_inputs(vec![second, first], common::scope());
    let forward_derived = derive_fixture(&forward);
    let reverse_derived = derive_fixture(&reverse);

    assert_eq!(forward_derived, reverse_derived);
    assert_eq!(
        serde_json::to_vec(&forward_derived).expect("forward bytes"),
        serde_json::to_vec(&reverse_derived).expect("reverse bytes")
    );
}

#[test]
fn governed_unit_relation_and_source_mutations_change_generation_commitments() {
    let baseline = derive_fixture(&fixture_fabric());

    let mut meaning_input = common::package_input("");
    meaning_input.units[0]
        .unit
        .meaning
        .push_str(" under policy");
    let meaning = derive_fixture(&fabric_from_inputs(vec![meaning_input], common::scope()));

    let mut relation_input = common::package_input("");
    relation_input.relations[0].relation_type = RelationType::Contradicts;
    let relation = derive_fixture(&fabric_from_inputs(vec![relation_input], common::scope()));

    let source = derive_fixture(&fabric_from_inputs(
        vec![common::package_input("# shifted source\n")],
        common::scope(),
    ));

    for changed in [&meaning, &relation, &source] {
        assert_ne!(
            baseline.generation.fabric_root,
            changed.generation.fabric_root
        );
        assert_ne!(
            baseline.catalogue.identity.catalogue_root,
            changed.catalogue.identity.catalogue_root
        );
        assert_ne!(baseline.proof_digest, changed.proof_digest);
    }
}

#[test]
fn operation_units_are_indexed_as_identities_and_never_inferred_as_operations() {
    let mut operation_input = common::package_input("");
    operation_input.units[0].unit.kind = UnitKind::Operation;
    operation_input.units[0].unit.expression = "observe".to_owned();
    operation_input.units[0].unit.aliases = BTreeSet::from(["inspect".to_owned()]);
    operation_input.units[0].unit.status = UnitStatus::Validated;
    let mut typed_scope = common::scope();
    typed_scope.semantic_kinds.insert(UnitKind::Operation);
    let fabric = fabric_from_inputs(vec![operation_input], typed_scope);
    let derived = derive_fixture(&fabric);

    assert!(derived.catalogue.operation_entries.is_empty());
    assert!(derived.catalogue.applicability_bindings.is_empty());
    assert!(
        derived
            .catalogue
            .identity_entries
            .iter()
            .any(|entry| entry.address.unit_id == id("unit:bank_financial")
                && entry.address.kind == UnitKind::Operation)
    );
    assert_eq!(derived.omissions.len(), 1);
    let omission = &derived.omissions[0];
    assert_eq!(omission.unit_id, id("unit:bank_financial"));
    assert!(omission.omitted_fields.contains("operation_class"));
    assert!(omission.omitted_fields.contains("roles"));
    assert!(omission.omitted_fields.contains("effect_class"));
    assert!(omission.omitted_fields.contains("applicability_bindings"));
    assert!(omission.reason.contains("inference is prohibited"));
    validate_derived_semantic_anchor_catalogue(&derived, &fabric).expect("omission proof");
}

#[test]
fn derived_projection_index_root_and_proof_tampering_fail_closed() {
    let fabric = fixture_fabric();
    let derived = derive_fixture(&fabric);

    let mut missing_label = derived.clone();
    missing_label.exact_label_index.remove("bank");
    assert_eq!(
        validate_derived_semantic_anchor_catalogue(&missing_label, &fabric)
            .expect_err("label tampering")
            .kind,
        AnchorDerivationFaultKind::ProjectionMismatch
    );

    let mut wrong_proof = derived.clone();
    wrong_proof.proof_digest.value.replace_range(0..1, "f");
    assert_eq!(
        validate_derived_semantic_anchor_catalogue(&wrong_proof, &fabric)
            .expect_err("proof tampering")
            .kind,
        AnchorDerivationFaultKind::ProjectionMismatch
    );

    let mut wrong_root = derived;
    wrong_root
        .catalogue
        .identity
        .catalogue_root
        .value
        .replace_range(0..1, "f");
    assert_eq!(
        validate_derived_semantic_anchor_catalogue(&wrong_root, &fabric)
            .expect_err("root tampering")
            .kind,
        AnchorDerivationFaultKind::InvalidCatalogue
    );

    let mut missing_source = derive_fixture(&fabric);
    missing_source.catalogue.identity_entries[0]
        .address
        .source_anchors
        .clear();
    missing_source.catalogue.identity.catalogue_root =
        catalogue_root(&missing_source.catalogue).expect("tampered catalogue root");
    missing_source.proof_digest =
        derived_semantic_anchor_catalogue_digest(&missing_source).expect("tampered proof digest");
    assert_eq!(
        validate_derived_semantic_anchor_catalogue(&missing_source, &fabric)
            .expect_err("missing source proof")
            .kind,
        AnchorDerivationFaultKind::ProjectionMismatch
    );
}

#[test]
fn logical_revision_is_required_and_committed_without_changing_fabric_identity() {
    let fabric = fixture_fabric();
    let empty = derive_semantic_anchor_catalogue(
        &fabric,
        CatalogueDerivationRequest {
            catalogue_id: id("catalogue:derived_fixture"),
            logical_revision: " ".to_owned(),
        },
    )
    .expect_err("empty logical revision");
    assert_eq!(empty.kind, AnchorDerivationFaultKind::InvalidRequest);

    let first = derive_fixture(&fabric);
    let second = derive_semantic_anchor_catalogue(
        &fabric,
        CatalogueDerivationRequest {
            catalogue_id: id("catalogue:derived_fixture"),
            logical_revision: "fixture-generation-r2".to_owned(),
        },
    )
    .expect("second logical revision");
    assert_eq!(first.generation.fabric_root, second.generation.fabric_root);
    assert_ne!(
        first.catalogue.identity.catalogue_root,
        second.catalogue.identity.catalogue_root
    );
    assert_ne!(first.proof_digest, second.proof_digest);
}

#[test]
fn derived_catalogue_machine_form_rejects_unknown_fields() {
    let derived = derive_fixture(&fixture_fabric());
    let mut value = serde_json::to_value(&derived).expect("derived value");
    value
        .as_object_mut()
        .expect("derived object")
        .insert("unrecognized_authority".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<DerivedSemanticAnchorCatalogue>(value).is_err());
}

#[test]
fn lexical_sidecar_closed_forms_validate_and_deny_unknown_fields() {
    let index = lexical_index_form();
    validate_derived_lexical_association_index_form(&index).expect("valid lexical sidecar form");

    let request = LexicalIndexDerivationRequest {
        index_id: id("lexical-index:fixture"),
        logical_revision: "fixture-r1".to_owned(),
        tokenizer_profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
    };
    validate_lexical_index_derivation_request(&request).expect("valid lexical request form");

    let mut index_value = serde_json::to_value(&index).expect("lexical index value");
    index_value
        .as_object_mut()
        .expect("lexical index object")
        .insert("authority_score".to_owned(), serde_json::json!(10_000));
    assert!(serde_json::from_value::<DerivedLexicalAssociationIndex>(index_value).is_err());

    let mut posting_value =
        serde_json::to_value(&index.postings["anchor"][0]).expect("lexical posting value");
    posting_value
        .as_object_mut()
        .expect("lexical posting object")
        .insert("permission".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<LexicalPosting>(posting_value).is_err());
}

#[test]
fn lexical_sidecar_request_profile_and_bounds_fail_closed() {
    let mut request = LexicalIndexDerivationRequest {
        index_id: id("lexical-index:fixture"),
        logical_revision: "fixture-r1".to_owned(),
        tokenizer_profile: "cantor-lexical-tokenizer/9.9".to_owned(),
    };
    assert_eq!(
        validate_lexical_index_derivation_request(&request)
            .expect_err("unsupported tokenizer profile")
            .kind,
        LexicalIndexFaultKind::InvalidProfile
    );
    request.tokenizer_profile = LEXICAL_TOKENIZER_PROFILE.to_owned();
    request.logical_revision = "x".repeat(257);
    assert_eq!(
        validate_lexical_index_derivation_request(&request)
            .expect_err("oversized logical revision")
            .kind,
        LexicalIndexFaultKind::InvalidBound
    );
}

#[test]
fn lexical_sidecar_structural_mutations_fail_closed() {
    let baseline = lexical_index_form();

    let mut wrong_profile = baseline.clone();
    wrong_profile.profile = "cantor-derived-lexical-association-index/9.9".to_owned();
    assert_eq!(
        validate_derived_lexical_association_index_form(&wrong_profile)
            .expect_err("wrong index profile")
            .kind,
        LexicalIndexFaultKind::InvalidProfile
    );

    let mut wrong_compiler = baseline.clone();
    wrong_compiler.compiler_id = id("compiler:other");
    assert_eq!(
        validate_derived_lexical_association_index_form(&wrong_compiler)
            .expect_err("wrong compiler")
            .kind,
        LexicalIndexFaultKind::InvalidIdentity
    );

    let mut wrong_fixture = baseline.clone();
    wrong_fixture
        .tokenizer
        .adversarial_fixture_digest
        .value
        .replace_range(0..1, "f");
    assert_eq!(
        validate_derived_lexical_association_index_form(&wrong_fixture)
            .expect_err("wrong tokenizer fixture digest")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut uppercase_token = baseline.clone();
    let mut postings = uppercase_token
        .postings
        .remove("anchor")
        .expect("anchor postings");
    postings[0].token = "Anchor".to_owned();
    uppercase_token
        .postings
        .insert("Anchor".to_owned(), postings);
    assert_eq!(
        validate_derived_lexical_association_index_form(&uppercase_token)
            .expect_err("uppercase token")
            .kind,
        LexicalIndexFaultKind::InvalidBound
    );

    let mut mismatched_token = baseline.clone();
    mismatched_token
        .postings
        .get_mut("anchor")
        .expect("posting")[0]
        .token = "different".to_owned();
    assert_eq!(
        validate_derived_lexical_association_index_form(&mismatched_token)
            .expect_err("posting token mismatch")
            .kind,
        LexicalIndexFaultKind::InvalidIdentity
    );

    let mut zero_occurrence = baseline.clone();
    zero_occurrence.postings.get_mut("anchor").expect("posting")[0].occurrence_count = 0;
    assert_eq!(
        validate_derived_lexical_association_index_form(&zero_occurrence)
            .expect_err("zero occurrence")
            .kind,
        LexicalIndexFaultKind::InvalidBound
    );

    let mut no_evidence = baseline.clone();
    no_evidence.postings.get_mut("anchor").expect("posting")[0]
        .evidence_refs
        .clear();
    assert_eq!(
        validate_derived_lexical_association_index_form(&no_evidence)
            .expect_err("missing evidence")
            .kind,
        LexicalIndexFaultKind::InvalidBound
    );

    let mut duplicate = baseline.clone();
    let repeated = duplicate.postings["anchor"][0].clone();
    duplicate
        .postings
        .get_mut("anchor")
        .expect("posting")
        .push(repeated);
    assert_eq!(
        validate_derived_lexical_association_index_form(&duplicate)
            .expect_err("duplicate posting")
            .kind,
        LexicalIndexFaultKind::DuplicatePosting
    );

    let mut wrong_order = baseline;
    let mut earlier = wrong_order.postings["anchor"][0].clone();
    earlier.address = address("unit:aaa", UnitKind::Declaration, '9');
    wrong_order
        .postings
        .get_mut("anchor")
        .expect("posting")
        .push(earlier);
    assert_eq!(
        validate_derived_lexical_association_index_form(&wrong_order)
            .expect_err("noncanonical posting order")
            .kind,
        LexicalIndexFaultKind::NonCanonicalOrder
    );
}

#[test]
fn lexical_tokenizer_follows_declared_unicode_and_separator_contract() {
    assert_eq!(
        tokenize_lexical_surface(" Anchor,ANCHOR ").expect("ASCII tokens"),
        BTreeMap::from([("anchor".to_owned(), 2)])
    );
    assert_eq!(
        tokenize_lexical_surface("R2D2 v1.0").expect("numeric tokens"),
        BTreeMap::from([
            ("0".to_owned(), 1),
            ("r2d2".to_owned(), 1),
            ("v1".to_owned(), 1),
        ])
    );
    assert_eq!(
        tokenize_lexical_surface("ÉLAN 東京 ١٢٣").expect("non-Latin tokens"),
        BTreeMap::from([
            ("élan".to_owned(), 1),
            ("١٢٣".to_owned(), 1),
            ("東京".to_owned(), 1),
        ])
    );
    assert_eq!(
        tokenize_lexical_surface("İ").expect("expanding lowercase token"),
        BTreeMap::from([("i".to_owned(), 1)])
    );
    assert_eq!(
        tokenize_lexical_surface("e\u{301} é").expect("no normalization"),
        BTreeMap::from([("e".to_owned(), 1), ("é".to_owned(), 1)])
    );
    assert!(
        tokenize_lexical_surface("---")
            .expect("empty token surface")
            .is_empty()
    );
    assert_eq!(
        tokenize_lexical_surface("A_B").expect("underscore separator"),
        BTreeMap::from([("a".to_owned(), 1), ("b".to_owned(), 1)])
    );
}

#[test]
fn lexical_tokenizer_bounds_and_fixture_digest_are_deterministic() {
    assert_eq!(
        tokenize_lexical_surface(&"x".repeat(MAX_LEXICAL_SURFACE_BYTES + 1))
            .expect_err("surface byte bound")
            .kind,
        LexicalIndexFaultKind::InvalidBound
    );
    assert_eq!(
        tokenize_lexical_surface(&"x".repeat(257))
            .expect_err("token byte bound")
            .kind,
        LexicalIndexFaultKind::InvalidBound
    );
    assert_eq!(
        tokenize_lexical_surface(&"a ".repeat(4097))
            .expect_err("token occurrence bound")
            .kind,
        LexicalIndexFaultKind::InvalidBound
    );
    let first = lexical_tokenizer_adversarial_fixture_digest().expect("fixture digest");
    let second = lexical_tokenizer_adversarial_fixture_digest().expect("repeat fixture digest");
    assert_eq!(first, second);
    assert_eq!(first.algorithm, "sha256");
    assert_eq!(
        first.value,
        "90a9cd4be7a9173f5aa15ba6b9c224a269b76c5f617ab4bc25f6e700a1e3deb9"
    );
}

#[test]
fn lexical_sidecar_derives_preferred_alias_and_meaning_surfaces() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let request = lexical_derivation_request();
    let index = derive_lexical_association_index(&fabric, &catalogue, request.clone())
        .expect("lexical sidecar derives");

    validate_derived_lexical_association_index(&index, &catalogue, &fabric)
        .expect("whole lexical replay");
    assert_eq!(
        index.catalogue_root,
        catalogue.catalogue.identity.catalogue_root
    );
    assert_eq!(index.fabric_root, catalogue.catalogue.identity.fabric_root);
    assert_eq!(
        index.index_root,
        lexical_association_index_root(&index).unwrap()
    );
    assert_eq!(
        index.proof_digest,
        lexical_association_index_proof_digest(&index, &request, &catalogue).unwrap()
    );

    let bank = &index.postings["bank"];
    assert_eq!(bank.len(), 2);
    assert!(
        bank.iter()
            .all(|posting| posting.surface_kind == LexicalSurfaceKind::PreferredExpression)
    );
    assert_eq!(bank[0].address.unit_id, id("unit:bank_financial"));
    assert_eq!(bank[1].address.unit_id, id("unit:bank_river"));

    let institution = &index.postings["institution"];
    assert_eq!(institution.len(), 2);
    assert_eq!(institution[0].surface_kind, LexicalSurfaceKind::Alias);
    assert_eq!(institution[1].surface_kind, LexicalSurfaceKind::Meaning);
    assert_ne!(institution[0].surface_digest, institution[1].surface_digest);

    for token_postings in index.postings.values() {
        for posting in token_postings {
            let entry = catalogue
                .catalogue
                .identity_entries
                .iter()
                .find(|entry| entry.address.unit_id == posting.address.unit_id)
                .expect("posting exact-resolves in catalogue");
            assert_eq!(posting.address, entry.address);
            assert!(posting.evidence_refs.contains(&entry.address.unit_id));
            assert!(posting.evidence_refs.contains(&entry.address.package_id));
            assert!(posting.evidence_refs.contains(&entry.address.context_id));
            assert!(posting.evidence_refs.contains(&entry.meaning_ref));
            for source in &entry.address.source_anchors {
                assert!(posting.evidence_refs.contains(&source.file_id));
                assert!(posting.evidence_refs.contains(&source.clause_id));
            }
        }
    }
}

#[test]
fn lexical_sidecar_counts_repetition_without_collapsing_distinct_surfaces() {
    let mut input = common::package_input("");
    input.units[0].unit.expression = "Bank BANK".to_owned();
    input.units[0].unit.aliases.insert("bank bank".to_owned());
    input.units[0].unit.aliases.insert("---".to_owned());
    let fabric = fabric_from_inputs(vec![input], common::scope());
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar derives");

    let financial = index.postings["bank"]
        .iter()
        .filter(|posting| posting.address.unit_id == id("unit:bank_financial"))
        .collect::<Vec<_>>();
    assert_eq!(financial.len(), 2);
    assert_eq!(
        financial[0].surface_kind,
        LexicalSurfaceKind::PreferredExpression
    );
    assert_eq!(financial[0].occurrence_count, 2);
    assert_eq!(financial[1].surface_kind, LexicalSurfaceKind::Alias);
    assert_eq!(financial[1].occurrence_count, 2);
    assert_ne!(financial[0].surface_digest, financial[1].surface_digest);
    assert!(!index.postings.contains_key("---"));
    validate_derived_lexical_association_index(&index, &catalogue, &fabric)
        .expect("repeated surface replay");
}

#[test]
fn lexical_sidecar_equal_inputs_are_byte_identical_and_revision_bound() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let request = lexical_derivation_request();
    let first = derive_lexical_association_index(&fabric, &catalogue, request.clone())
        .expect("first sidecar");
    let second =
        derive_lexical_association_index(&fabric, &catalogue, request).expect("second sidecar");
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );

    let revised = derive_lexical_association_index(
        &fabric,
        &catalogue,
        LexicalIndexDerivationRequest {
            index_id: first.index_id.clone(),
            logical_revision: "fixture-lexical-r2".to_owned(),
            tokenizer_profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
        },
    )
    .expect("revised sidecar");
    assert_ne!(first.index_root, revised.index_root);
    assert_ne!(first.proof_digest, revised.proof_digest);
    assert_eq!(first.catalogue_root, revised.catalogue_root);
    assert_eq!(first.fabric_root, revised.fabric_root);
}

#[test]
fn lexical_sidecar_whole_replay_rejects_self_consistent_posting_mutations() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let request = lexical_derivation_request();
    let baseline = derive_lexical_association_index(&fabric, &catalogue, request.clone())
        .expect("baseline sidecar");

    let mut missing = baseline.clone();
    missing
        .postings
        .remove("deposits")
        .expect("deposits posting");
    reseal_lexical_index(&mut missing, &request, &catalogue);
    validate_derived_lexical_association_index_form(&missing).expect("self-consistent form");
    assert_eq!(
        validate_derived_lexical_association_index(&missing, &catalogue, &fabric)
            .expect_err("missing posting")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut occurrence = baseline.clone();
    occurrence.postings.get_mut("deposits").unwrap()[0].occurrence_count = 2;
    reseal_lexical_index(&mut occurrence, &request, &catalogue);
    validate_derived_lexical_association_index_form(&occurrence).expect("occurrence form");
    assert_eq!(
        validate_derived_lexical_association_index(&occurrence, &catalogue, &fabric)
            .expect_err("wrong occurrence")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut evidence = baseline;
    let removable = evidence.postings["deposits"][0]
        .evidence_refs
        .iter()
        .next()
        .cloned()
        .unwrap();
    evidence.postings.get_mut("deposits").unwrap()[0]
        .evidence_refs
        .remove(&removable);
    reseal_lexical_index(&mut evidence, &request, &catalogue);
    validate_derived_lexical_association_index_form(&evidence).expect("evidence form");
    assert_eq!(
        validate_derived_lexical_association_index(&evidence, &catalogue, &fabric)
            .expect_err("wrong evidence")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut surface_digest =
        derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
            .expect("surface mutation baseline");
    surface_digest.postings.get_mut("deposits").unwrap()[0].surface_digest = digest('6');
    reseal_lexical_index(&mut surface_digest, &request, &catalogue);
    validate_derived_lexical_association_index_form(&surface_digest)
        .expect("self-consistent surface digest form");
    assert_eq!(
        validate_derived_lexical_association_index(&surface_digest, &catalogue, &fabric)
            .expect_err("wrong surface digest")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut source_span =
        derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
            .expect("source mutation baseline");
    source_span.postings.get_mut("deposits").unwrap()[0]
        .address
        .source_anchors[0]
        .span_digest = digest('5');
    reseal_lexical_index(&mut source_span, &request, &catalogue);
    validate_derived_lexical_association_index_form(&source_span)
        .expect("self-consistent source mutation form");
    assert_eq!(
        validate_derived_lexical_association_index(&source_span, &catalogue, &fabric)
            .expect_err("wrong source span digest")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut addition =
        derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
            .expect("addition baseline");
    let mut invented = addition.postings["deposits"][0].clone();
    invented.token = "invented".to_owned();
    invented.surface_digest = digest('4');
    addition
        .postings
        .insert("invented".to_owned(), vec![invented]);
    reseal_lexical_index(&mut addition, &request, &catalogue);
    validate_derived_lexical_association_index_form(&addition)
        .expect("self-consistent posting addition form");
    assert_eq!(
        validate_derived_lexical_association_index(&addition, &catalogue, &fabric)
            .expect_err("invented posting")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );
}

#[test]
fn lexical_sidecar_refuses_self_consistent_stale_meaning_and_package_catalogues() {
    let fabric = fixture_fabric();
    let canonical = derive_fixture(&fabric);

    let mut wrong_meaning = canonical.clone();
    wrong_meaning.catalogue.identity_entries[0].meaning_ref = id("meaning:invented");
    reseal_derived_catalogue(&mut wrong_meaning);
    validate_semantic_anchor_catalogue(&wrong_meaning.catalogue)
        .expect("mutated meaning catalogue is structurally self-consistent");
    assert_eq!(
        derive_lexical_association_index(&fabric, &wrong_meaning, lexical_derivation_request(),)
            .expect_err("stale meaning correspondence")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut wrong_package = canonical;
    let invented_package_digest = digest('3');
    for entry in &mut wrong_package.catalogue.identity_entries {
        entry.address.package_digest = invented_package_digest.clone();
    }
    for entry in &mut wrong_package.catalogue.operation_entries {
        entry.address.package_digest = invented_package_digest.clone();
    }
    for package_digest in wrong_package.catalogue.identity.package_roots.values_mut() {
        *package_digest = invented_package_digest.clone();
    }
    reseal_derived_catalogue(&mut wrong_package);
    validate_semantic_anchor_catalogue(&wrong_package.catalogue)
        .expect("mutated package catalogue is structurally self-consistent");
    assert_eq!(
        derive_lexical_association_index(&fabric, &wrong_package, lexical_derivation_request(),)
            .expect_err("stale package correspondence")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );
}

#[test]
fn lexical_sidecar_roots_and_proof_fail_closed() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let request = lexical_derivation_request();
    let baseline = derive_lexical_association_index(&fabric, &catalogue, request.clone())
        .expect("baseline sidecar");

    let mut wrong_index_root = baseline.clone();
    wrong_index_root.index_root = digest('9');
    assert_eq!(
        validate_derived_lexical_association_index_form(&wrong_index_root)
            .expect_err("wrong index root")
            .kind,
        LexicalIndexFaultKind::RootMismatch
    );

    let mut wrong_proof = baseline.clone();
    wrong_proof.proof_digest = digest('8');
    assert_eq!(
        validate_derived_lexical_association_index(&wrong_proof, &catalogue, &fabric)
            .expect_err("wrong proof")
            .kind,
        LexicalIndexFaultKind::ProjectionMismatch
    );

    let mut stale_catalogue_root = baseline;
    stale_catalogue_root.catalogue_root = digest('7');
    reseal_lexical_index(&mut stale_catalogue_root, &request, &catalogue);
    assert_eq!(
        validate_derived_lexical_association_index(&stale_catalogue_root, &catalogue, &fabric)
            .expect_err("stale catalogue root")
            .kind,
        LexicalIndexFaultKind::RootMismatch
    );

    let mut stale_fabric_root =
        derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
            .expect("fabric-root mutation baseline");
    stale_fabric_root.fabric_root = digest('6');
    reseal_lexical_index(&mut stale_fabric_root, &request, &catalogue);
    assert_eq!(
        validate_derived_lexical_association_index(&stale_fabric_root, &catalogue, &fabric)
            .expect_err("stale fabric root")
            .kind,
        LexicalIndexFaultKind::RootMismatch
    );
}

#[test]
fn lexical_lookup_orders_unique_token_coverage_and_retains_exact_evidence() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["Bank deposits"]);
    let result = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("lexical lookup");

    validate_lexical_anchor_lookup_result(&result, &request, &index, &catalogue, &fabric)
        .expect("whole lexical lookup replay");
    assert_eq!(
        result.eligible_tokens,
        BTreeSet::from(["bank".to_owned(), "deposits".to_owned()])
    );
    assert!(result.unmatched_tokens.is_empty());
    assert_eq!(result.matches[0].address.unit_id, id("unit:bank_financial"));
    assert_eq!(result.matches[0].coverage_basis_points, 10_000);
    assert_eq!(
        result.matches[0].matched_tokens,
        BTreeSet::from(["bank".to_owned(), "deposits".to_owned()])
    );
    assert_eq!(result.matches[1].address.unit_id, id("unit:bank_river"));
    assert_eq!(result.matches[1].coverage_basis_points, 5_000);
    assert_eq!(
        result.non_authority_statement,
        LEXICAL_ANCHOR_LOOKUP_NON_AUTHORITY
    );
    for candidate in &result.matches {
        assert!(!candidate.evidence.is_empty());
        for evidence in &candidate.evidence {
            assert!(candidate.matched_tokens.contains(&evidence.token));
            assert!(evidence.occurrence_count > 0);
            assert!(evidence.evidence_refs.contains(&candidate.address.unit_id));
            assert!(
                evidence
                    .evidence_refs
                    .contains(&candidate.address.package_id)
            );
        }
    }
}

#[test]
fn lexical_lookup_duplicate_terms_and_occurrences_do_not_inflate_coverage() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["bank bank", "BANK"]);
    let first =
        lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone()).expect("first lookup");
    let second = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("second lookup");

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(first.term_accounts.len(), 2);
    assert_eq!(first.term_accounts[0].token_occurrences["bank"], 2);
    assert_eq!(first.term_accounts[1].token_occurrences["bank"], 1);
    assert_eq!(first.eligible_tokens, BTreeSet::from(["bank".to_owned()]));
    assert_eq!(first.matches.len(), 2);
    assert!(
        first
            .matches
            .iter()
            .all(|candidate| candidate.coverage_basis_points == 10_000)
    );
    assert_eq!(first.matches[0].address.unit_id, id("unit:bank_financial"));
    assert_eq!(first.matches[1].address.unit_id, id("unit:bank_river"));
    validate_lexical_anchor_lookup_result_form(&first, &request, &index, &catalogue)
        .expect("index-bound replay");
}

#[test]
fn lexical_lookup_substrings_missing_tokens_and_empty_token_terms_are_explicit() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");

    let substring_request = lexical_lookup_request(&["ank absent-token"]);
    let substring = lookup_lexical_anchors(&fabric, &catalogue, &index, substring_request.clone())
        .expect("substring lookup");
    assert!(substring.matches.is_empty());
    assert_eq!(
        substring.unmatched_tokens,
        BTreeSet::from(["absent".to_owned(), "ank".to_owned(), "token".to_owned()])
    );
    validate_lexical_anchor_lookup_result(
        &substring,
        &substring_request,
        &index,
        &catalogue,
        &fabric,
    )
    .expect("empty lookup replay");

    let punctuation_request = lexical_lookup_request(&["---"]);
    let punctuation =
        lookup_lexical_anchors(&fabric, &catalogue, &index, punctuation_request.clone())
            .expect("empty-token lookup");
    assert!(punctuation.eligible_tokens.is_empty());
    assert!(punctuation.unmatched_tokens.is_empty());
    assert!(punctuation.matches.is_empty());
    assert_eq!(punctuation.complete_posting_count, 0);
}

#[test]
fn lexical_lookup_request_and_complete_union_budgets_fail_before_partial_results() {
    let mut invalid = lexical_lookup_request(&["bank"]);
    invalid.profile = "cantor-lexical-anchor-lookup/9.9".to_owned();
    assert_eq!(
        validate_lexical_anchor_lookup_request(&invalid)
            .expect_err("unsupported lookup profile")
            .kind,
        LexicalLookupFaultKind::InvalidProfile
    );
    invalid = lexical_lookup_request(&["bank"]);
    invalid.terms[0] = " ".to_owned();
    assert_eq!(
        validate_lexical_anchor_lookup_request(&invalid)
            .expect_err("blank lookup term")
            .kind,
        LexicalLookupFaultKind::InvalidBound
    );

    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let mut posting_budget = lexical_lookup_request(&["bank"]);
    posting_budget.budget.maximum_postings = 1;
    assert_eq!(
        lookup_lexical_anchors(&fabric, &catalogue, &index, posting_budget)
            .expect_err("complete posting budget")
            .kind,
        LexicalLookupFaultKind::BudgetExceeded
    );
    let mut match_budget = lexical_lookup_request(&["bank"]);
    match_budget.budget.maximum_matches = 1;
    assert_eq!(
        lookup_lexical_anchors(&fabric, &catalogue, &index, match_budget)
            .expect_err("complete match budget")
            .kind,
        LexicalLookupFaultKind::BudgetExceeded
    );
    let mut token_budget = lexical_lookup_request(&["bank deposits"]);
    token_budget.budget.maximum_unique_tokens = 1;
    assert_eq!(
        lookup_lexical_anchors(&fabric, &catalogue, &index, token_budget)
            .expect_err("complete token budget")
            .kind,
        LexicalLookupFaultKind::BudgetExceeded
    );
    let mut result_bytes = lexical_lookup_request(&["bank"]);
    result_bytes.budget.maximum_serialized_result_bytes = 1;
    assert_eq!(
        lookup_lexical_anchors(&fabric, &catalogue, &index, result_bytes)
            .expect_err("complete result byte budget")
            .kind,
        LexicalLookupFaultKind::BudgetExceeded
    );
}

#[test]
fn lexical_lookup_proof_and_whole_replay_reject_self_consistent_mutation() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["bank deposits"]);
    let baseline = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("lookup baseline");

    let mut wrong_proof = baseline.clone();
    wrong_proof.proof_digest = digest('2');
    assert_eq!(
        validate_lexical_anchor_lookup_result_form(&wrong_proof, &request, &index, &catalogue,)
            .expect_err("wrong lookup proof")
            .kind,
        LexicalLookupFaultKind::ProofMismatch
    );

    let mut resealed = baseline.clone();
    resealed.matches[0].coverage_basis_points = 9_999;
    resealed.proof_digest =
        lexical_anchor_lookup_proof_digest(&resealed, &request, &index, &catalogue)
            .expect("resealed lookup proof");
    assert_eq!(
        validate_lexical_anchor_lookup_result(&resealed, &request, &index, &catalogue, &fabric,)
            .expect_err("self-consistent coverage mutation")
            .kind,
        LexicalLookupFaultKind::ProjectionMismatch
    );

    let mut evidence = baseline.clone();
    evidence.matches[0].evidence[0].occurrence_count += 1;
    evidence.proof_digest =
        lexical_anchor_lookup_proof_digest(&evidence, &request, &index, &catalogue)
            .expect("resealed evidence proof");
    assert_eq!(
        validate_lexical_anchor_lookup_result(&evidence, &request, &index, &catalogue, &fabric,)
            .expect_err("self-consistent evidence mutation")
            .kind,
        LexicalLookupFaultKind::ProjectionMismatch
    );

    let mut reordered = baseline;
    reordered.matches.swap(0, 1);
    reordered.proof_digest =
        lexical_anchor_lookup_proof_digest(&reordered, &request, &index, &catalogue)
            .expect("resealed order proof");
    assert_eq!(
        validate_lexical_anchor_lookup_result(&reordered, &request, &index, &catalogue, &fabric,)
            .expect_err("self-consistent order mutation")
            .kind,
        LexicalLookupFaultKind::ProjectionMismatch
    );
}

#[test]
fn lexical_lookup_forms_deny_unknown_fields_and_stale_index_identity() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["bank"]);
    let result = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("lookup result");

    let mut request_value = serde_json::to_value(&request).unwrap();
    request_value
        .as_object_mut()
        .unwrap()
        .insert("authority".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<LexicalAnchorLookupRequest>(request_value).is_err());

    let mut result_value = serde_json::to_value(&result).unwrap();
    result_value
        .as_object_mut()
        .unwrap()
        .insert("truth".to_owned(), serde_json::json!(true));
    assert!(
        serde_json::from_value::<cantor_core::LexicalAnchorLookupResult>(result_value).is_err()
    );

    let mut stale_index = index;
    stale_index.index_root = digest('3');
    assert_eq!(
        lookup_lexical_anchors(&fabric, &catalogue, &stale_index, request)
            .expect_err("stale lexical index")
            .kind,
        LexicalLookupFaultKind::RootMismatch
    );
}

#[test]
fn lexical_source_projection_returns_exact_admitted_paths_lines_text_and_proof() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["bank deposits"]);
    let lookup = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("lexical lookup");
    let budget = lexical_source_projection_budget();
    let first = project_lexical_anchor_sources(
        &fabric,
        &catalogue,
        &index,
        &request,
        &lookup,
        budget.clone(),
    )
    .expect("source projection");
    let second = project_lexical_anchor_sources(
        &fabric,
        &catalogue,
        &index,
        &request,
        &lookup,
        budget.clone(),
    )
    .expect("repeated source projection");

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(first.lookup_proof_digest, lookup.proof_digest);
    assert_eq!(first.projections.len(), lookup.matches.len());
    assert_eq!(
        first.projections[0].address.unit_id,
        id("unit:bank_financial")
    );
    assert_eq!(
        first.projections[0].source_path,
        "fixtures/bank_financial.sop"
    );
    assert_eq!(
        first.projections[0].text,
        "& [bank_financial] is a financial institution"
    );
    assert_eq!(first.projections[0].source_anchor.display_line_start, 1);
    assert_eq!(first.projections[0].source_anchor.display_line_end, 1);
    assert!(!first.projections[0].certificate_id.as_str().is_empty());
    validate_lexical_anchor_source_projection_result(
        &first, &fabric, &catalogue, &index, &request, &lookup, &budget,
    )
    .expect("whole source projection replay");
}

#[test]
fn lexical_source_projection_refuses_incomplete_projection_and_quote_budgets() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["bank"]);
    let lookup = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("ambiguous lexical lookup");

    let mut projection_bound = lexical_source_projection_budget();
    projection_bound.maximum_projections = 1;
    assert_eq!(
        project_lexical_anchor_sources(
            &fabric,
            &catalogue,
            &index,
            &request,
            &lookup,
            projection_bound,
        )
        .expect_err("complete projection budget")
        .kind,
        LexicalSourceProjectionFaultKind::BudgetExceeded
    );

    let mut quote_bound = lexical_source_projection_budget();
    quote_bound.maximum_quote_bytes = 1;
    assert_eq!(
        project_lexical_anchor_sources(
            &fabric,
            &catalogue,
            &index,
            &request,
            &lookup,
            quote_bound,
        )
        .expect_err("complete quote budget")
        .kind,
        LexicalSourceProjectionFaultKind::BudgetExceeded
    );

    let mut result_bound = lexical_source_projection_budget();
    result_bound.maximum_serialized_result_bytes = 1;
    assert_eq!(
        project_lexical_anchor_sources(
            &fabric,
            &catalogue,
            &index,
            &request,
            &lookup,
            result_bound,
        )
        .expect_err("complete serialized result budget")
        .kind,
        LexicalSourceProjectionFaultKind::BudgetExceeded
    );
}

#[test]
fn lexical_source_projection_whole_replay_rejects_self_consistent_source_mutation() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["bank"]);
    let lookup = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("lexical lookup");
    let budget = lexical_source_projection_budget();
    let baseline = project_lexical_anchor_sources(
        &fabric,
        &catalogue,
        &index,
        &request,
        &lookup,
        budget.clone(),
    )
    .expect("source projection baseline");

    let mut wrong_proof = baseline.clone();
    wrong_proof.proof_digest = digest('8');
    assert_eq!(
        validate_lexical_anchor_source_projection_result_form(&wrong_proof, &lookup, &budget)
            .expect_err("wrong source projection proof")
            .kind,
        LexicalSourceProjectionFaultKind::ProofMismatch
    );

    let mut resealed = baseline;
    resealed.projections[0].source_path = "fixtures/invented.sop".to_owned();
    resealed.projections[0].text = "invented admitted-looking text".to_owned();
    resealed.projections[0].certificate_id = id("certificate:invented");
    resealed.projections[0].projection_digest =
        lexical_anchor_source_projection_digest(&resealed.projections[0])
            .expect("resealed projection digest");
    resealed.proof_digest =
        lexical_anchor_source_projection_result_digest(&resealed, &lookup, &budget)
            .expect("resealed result digest");
    validate_lexical_anchor_source_projection_result_form(&resealed, &lookup, &budget)
        .expect("self-consistent source projection form");
    assert_eq!(
        validate_lexical_anchor_source_projection_result(
            &resealed, &fabric, &catalogue, &index, &request, &lookup, &budget,
        )
        .expect_err("self-consistent invented source")
        .kind,
        LexicalSourceProjectionFaultKind::ProjectionMismatch
    );
}

#[test]
fn lexical_source_projection_empty_match_and_unknown_fields_are_explicit() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let request = lexical_lookup_request(&["absent"]);
    let lookup = lookup_lexical_anchors(&fabric, &catalogue, &index, request.clone())
        .expect("empty lexical lookup");
    let budget = lexical_source_projection_budget();
    let projected =
        project_lexical_anchor_sources(&fabric, &catalogue, &index, &request, &lookup, budget)
            .expect("empty source projection");
    assert!(projected.projections.is_empty());

    let mut value = serde_json::to_value(&projected).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("live_file_verified".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<LexicalAnchorSourceProjectionResult>(value).is_err());
}

#[test]
fn lexical_seed_gate_is_deterministic_exact_identity_semantic_replay() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let lexical_request = lexical_lookup_request(&["Bank deposits"]);
    let lexical_result =
        lookup_lexical_anchors(&fabric, &catalogue, &index, lexical_request.clone())
            .expect("lexical lookup");
    let request = lexical_gate_request(&lexical_result);

    let result = gate_lexical_anchor_matches(
        &fabric,
        &catalogue,
        &index,
        &lexical_request,
        &lexical_result,
        request.clone(),
    )
    .expect("semantic gate");
    validate_lexically_seeded_anchor_gate_result(
        &result,
        &fabric,
        &catalogue,
        &index,
        &lexical_request,
        &lexical_result,
        &request,
    )
    .expect("whole semantic gate replay");
    assert_eq!(result.ordered_seed_ids.len(), 2);
    assert_eq!(result.scanner_result.candidates.len(), 2);
    assert_eq!(
        result.non_authority_statement,
        LEXICALLY_SEEDED_ANCHOR_GATE_NON_AUTHORITY
    );
    assert!(result.scanner_result.candidates.iter().all(|candidate| {
        candidate.priority_tier == PriorityTier::ExactIdentity
            && candidate
                .contributions
                .iter()
                .all(|contribution| contribution.channel == AssociationChannel::ExactIdentity)
    }));

    let repeated = gate_lexical_anchor_matches(
        &fabric,
        &catalogue,
        &index,
        &lexical_request,
        &lexical_result,
        request,
    )
    .expect("repeated semantic gate");
    assert_eq!(
        serde_json::to_vec(&result).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
}

#[test]
fn lexical_seed_gate_preserves_semantic_purpose_and_authority_dispositions() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let lexical_request = lexical_lookup_request(&["Bank deposits"]);
    let lexical_result =
        lookup_lexical_anchors(&fabric, &catalogue, &index, lexical_request.clone())
            .expect("lexical lookup");

    let mut excluded_request = lexical_gate_request(&lexical_result);
    excluded_request.scanner_query.purpose = "invented purpose".to_owned();
    let excluded = gate_lexical_anchor_matches(
        &fabric,
        &catalogue,
        &index,
        &lexical_request,
        &lexical_result,
        excluded_request,
    )
    .expect("purpose mismatch remains a semantic disposition");
    assert!(
        excluded
            .scanner_result
            .candidates
            .iter()
            .all(|candidate| { candidate.eligibility == CandidateEligibility::Excluded })
    );

    let mut unauthorized_request = lexical_gate_request(&lexical_result);
    unauthorized_request
        .scanner_query
        .authority_context
        .allowed_package_scopes = BTreeSet::from(["outside".to_owned()]);
    let unauthorized = gate_lexical_anchor_matches(
        &fabric,
        &catalogue,
        &index,
        &lexical_request,
        &lexical_result,
        unauthorized_request,
    )
    .expect("authority mismatch remains a semantic disposition");
    assert!(
        unauthorized
            .scanner_result
            .candidates
            .iter()
            .all(|candidate| { candidate.eligibility == CandidateEligibility::Unauthorized })
    );
}

#[test]
fn lexical_seed_gate_rejects_seed_channel_continuation_and_budget_mutations() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let lexical_request = lexical_lookup_request(&["Bank deposits"]);
    let lexical_result = lookup_lexical_anchors(&fabric, &catalogue, &index, lexical_request)
        .expect("lexical lookup");

    let mut changed = lexical_gate_request(&lexical_result);
    changed
        .scanner_query
        .known_identities
        .remove(&id("unit:bank_river"));
    assert_eq!(
        validate_lexically_seeded_anchor_gate_request(&changed, &lexical_result)
            .expect_err("missing lexical seed")
            .kind,
        LexicallySeededAnchorGateFaultKind::SeedMismatch
    );

    changed = lexical_gate_request(&lexical_result);
    changed
        .scanner_query
        .allowed_channels
        .insert(AssociationChannel::Lexical);
    assert_eq!(
        validate_lexically_seeded_anchor_gate_request(&changed, &lexical_result)
            .expect_err("lexical ranking cannot enter scanner")
            .kind,
        LexicallySeededAnchorGateFaultKind::QueryRejected
    );

    changed = lexical_gate_request(&lexical_result);
    changed.scanner_query.budget.maximum_continuations = 1;
    assert_eq!(
        validate_lexically_seeded_anchor_gate_request(&changed, &lexical_result)
            .expect_err("continuation is prohibited")
            .kind,
        LexicallySeededAnchorGateFaultKind::QueryRejected
    );

    changed = lexical_gate_request(&lexical_result);
    changed.scanner_query.budget.maximum_records = 17;
    assert_eq!(
        validate_lexically_seeded_anchor_gate_request(&changed, &lexical_result)
            .expect_err("scanner budget exceeds gate cap")
            .kind,
        LexicallySeededAnchorGateFaultKind::InvalidBound
    );
}

#[test]
fn lexical_seed_gate_rejects_result_tampering_and_unknown_fields() {
    let fabric = fixture_fabric();
    let catalogue = derive_fixture(&fabric);
    let index = derive_lexical_association_index(&fabric, &catalogue, lexical_derivation_request())
        .expect("lexical sidecar");
    let lexical_request = lexical_lookup_request(&["Bank deposits"]);
    let lexical_result =
        lookup_lexical_anchors(&fabric, &catalogue, &index, lexical_request.clone())
            .expect("lexical lookup");
    let request = lexical_gate_request(&lexical_result);
    let result = gate_lexical_anchor_matches(
        &fabric,
        &catalogue,
        &index,
        &lexical_request,
        &lexical_result,
        request.clone(),
    )
    .expect("semantic gate");

    let mut removed = result.clone();
    removed.scanner_result.candidates.pop();
    removed.proof_digest = lexically_seeded_anchor_gate_result_digest(&removed, &request)
        .expect("resealed outer proof");
    assert_eq!(
        validate_lexically_seeded_anchor_gate_result_form(&removed, &lexical_result, &request)
            .expect_err("missing scanner candidate")
            .kind,
        LexicallySeededAnchorGateFaultKind::ScannerRejected
    );

    let mut wrong_proof = result.clone();
    wrong_proof.proof_digest = digest('9');
    assert_eq!(
        validate_lexically_seeded_anchor_gate_result_form(&wrong_proof, &lexical_result, &request)
            .expect_err("wrong outer proof")
            .kind,
        LexicallySeededAnchorGateFaultKind::ProofMismatch
    );

    let mut request_value = serde_json::to_value(&request).unwrap();
    request_value.as_object_mut().unwrap().insert(
        "lexical_rank_is_authority".to_owned(),
        serde_json::json!(true),
    );
    assert!(serde_json::from_value::<LexicallySeededAnchorGateRequest>(request_value).is_err());

    let mut result_value = serde_json::to_value(&result).unwrap();
    result_value
        .as_object_mut()
        .unwrap()
        .insert("semantic_gate_bypassed".to_owned(), serde_json::json!(true));
    assert!(
        serde_json::from_value::<cantor_core::LexicallySeededAnchorGateResult>(result_value)
            .is_err()
    );
}
