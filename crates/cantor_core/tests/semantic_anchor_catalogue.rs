use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ANCHOR_QUERY_PROFILE, ANCHOR_QUERY_RESULT_PROFILE, AnchorBudget, AnchorCandidate,
    AnchorFormFaultKind, AnchorLifecycle, AnchorProof, AnchorQuery, AnchorQueryResult,
    ApplicabilityBinding, ApplicabilityStatus, AssociationChannel, AssociationContribution,
    AuthorityContext, BoundaryAccount, CandidateEligibility, CatalogueIdentity, ChannelLocalValue,
    ContentDigest, ContributionStatus, IdentityAnchorEntry, OperationAnchorEntry, OperationClass,
    OperationRole, PriorityTier, RelationType, RequestedDetailKind,
    SEMANTIC_ANCHOR_CATALOGUE_PROFILE, SemanticAddress, SemanticAnchorCatalogue, SemanticId,
    SourceAnchor, UnitKind, anchor_query_result_digest, catalogue_derivation_digest,
    catalogue_root, validate_anchor_candidate, validate_anchor_query, validate_anchor_query_result,
    validate_semantic_anchor_catalogue,
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
