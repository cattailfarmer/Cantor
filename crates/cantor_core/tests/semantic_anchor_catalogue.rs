use std::collections::{BTreeMap, BTreeSet};

mod common;

use cantor_core::{
    ANCHOR_QUERY_PROFILE, ANCHOR_QUERY_RESULT_PROFILE, AnchorBudget, AnchorCandidate,
    AnchorDerivationFaultKind, AnchorFormFaultKind, AnchorLifecycle, AnchorProof, AnchorQuery,
    AnchorQueryResult, ApplicabilityBinding, ApplicabilityStatus, AssociationChannel,
    AssociationContribution, AuthorityContext, AuthorityScope, BoundaryAccount,
    CandidateEligibility, CatalogueDerivationRequest, CatalogueIdentity, ChannelLocalValue,
    ContentDigest, ContributionStatus, DerivedSemanticAnchorCatalogue, IdentityAnchorEntry,
    OperationAnchorEntry, OperationClass, OperationRole, PriorityTier, RelationType,
    RequestedDetailKind, SEMANTIC_ANCHOR_CATALOGUE_PROFILE, SemanticAddress,
    SemanticAnchorCatalogue, SemanticFabric, SemanticId, SourceAnchor, UnitKind, UnitStatus,
    admit_package, anchor_query_result_digest, catalogue_derivation_digest, catalogue_root,
    derive_semantic_anchor_catalogue, derived_semantic_anchor_catalogue_digest,
    validate_anchor_candidate, validate_anchor_query, validate_anchor_query_result,
    validate_derived_semantic_anchor_catalogue, validate_semantic_anchor_catalogue,
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
    AssociationContribution {
        channel,
        candidate_address: address.clone(),
        basis: "fixture basis".to_owned(),
        channel_local_value,
        evidence_refs: BTreeSet::new(),
        conditions: BTreeSet::new(),
        unresolved_guards: BTreeSet::new(),
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
    let mut result = AnchorQueryResult {
        profile: ANCHOR_QUERY_RESULT_PROFILE.to_owned(),
        request_id: id("request:fixture"),
        catalogue_root: catalogue.identity.catalogue_root.clone(),
        fabric_root: catalogue.identity.fabric_root.clone(),
        candidates: vec![candidate],
        record_ids: vec![unit_id.clone()],
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
