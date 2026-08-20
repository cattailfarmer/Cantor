use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use cantor_core::{
    CANDIDATE_COMPILATION_PLAN_PROFILE, COMPILER_CAPABILITY_CEILING_PROFILE, CompilerBackendKind,
    CompilerCapability, CompilerCapabilityCeiling, LEXICAL_ANCHOR_LOOKUP_PROFILE,
    LEXICAL_TOKENIZER_PROFILE, LexicalAnchorLookupBudget, LexicalAnchorLookupRequest,
    LexicalAnchorSourceProjectionBudget, LexicalIndexDerivationRequest,
    PROVIDER_FREE_SELF_ORDERING_PROJECTION_PROFILE, SELF_ORDERING_REQUEST_PROFILE,
    SOP_SEED_PROFILE, SelfAssemblyDisposition, SelfAssemblyStage, SelfOrderingNodeDirective,
    SelfOrderingRequest, SemanticFabric, SemanticId, SemanticIrNodeKind, SopCorpusManifest,
    SopDocumentInput, SopSeed, SopSigningKeys, TYPED_SOP_IR_PROFILE, admit_package,
    build_sop_corpus, compiler_capability_ceiling_digest, derive_lexical_association_index,
    derive_semantic_anchor_catalogue, lookup_lexical_anchors, project_lexical_anchor_sources,
    project_provider_free_self_ordering, sop_seed_digest,
    validate_provider_free_self_ordering_projection,
};
use cantor_core::{CatalogueDerivationRequest, ContentDigest};
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest as _, Sha256};

const PURPOSE: &str =
    "order admitted Cantor self-description into one inert attention procedure plan";

struct Fixture {
    seed: SopSeed,
    fabric: cantor_core::SemanticFabric,
    catalogue: cantor_core::DerivedSemanticAnchorCatalogue,
    index: cantor_core::DerivedLexicalAssociationIndex,
    lookup_request: LexicalAnchorLookupRequest,
    lookup_result: cantor_core::LexicalAnchorLookupResult,
    source_budget: LexicalAnchorSourceProjectionBudget,
    source_projection: cantor_core::LexicalAnchorSourceProjectionResult,
    request: SelfOrderingRequest,
}

#[test]
fn tracked_self_hosted_corpus_projects_one_deterministic_inert_self_ordering_plan() {
    let fixture = fixture();
    let first = project(&fixture, fixture.request.clone()).expect("projection must succeed");
    let second = project(&fixture, fixture.request.clone()).expect("replay must succeed");

    assert_eq!(first, second);
    assert_eq!(
        first.profile,
        PROVIDER_FREE_SELF_ORDERING_PROJECTION_PROFILE
    );
    assert_eq!(first.ir.profile, TYPED_SOP_IR_PROFILE);
    assert_eq!(first.plan.profile, CANDIDATE_COMPILATION_PLAN_PROFILE);
    assert_eq!(first.plan.backend, CompilerBackendKind::AttentionProcedure);
    assert_eq!(first.ledger.entries.len(), 2);
    assert_eq!(
        first.ledger.entries[0].stage,
        SelfAssemblyStage::SelfDescription
    );
    assert_eq!(
        first.ledger.entries[0].disposition,
        SelfAssemblyDisposition::Observed
    );
    assert_eq!(
        first.ledger.entries[1].stage,
        SelfAssemblyStage::SelfOrdering
    );
    assert_eq!(
        first.ledger.entries[1].disposition,
        SelfAssemblyDisposition::Candidate
    );
    assert!(first.ledger.successor_generation_ref.is_none());
    assert!(first.ledger.entries.iter().all(|entry| {
        entry.candidate_artifact_ref.is_none()
            && entry.honesty_receipt_ref.is_none()
            && entry.security_receipt_ref.is_none()
            && entry.external_recognition_ref.is_none()
    }));
    validate(&fixture, &first).expect("projection must independently replay");

    let encoded = serde_json::to_vec(&first).expect("projection serializes");
    let decoded = serde_json::from_slice(&encoded).expect("projection decodes strictly");
    assert_eq!(first, decoded);
}

#[test]
fn dependency_proof_role_capability_and_machine_form_substitutions_fail_closed() {
    let fixture = fixture();
    let projection = project(&fixture, fixture.request.clone()).expect("baseline projects");

    let mut capability_excess = fixture.request.clone();
    capability_excess
        .requested_capabilities
        .insert(CompilerCapability::ProcessExecute);
    assert!(project(&fixture, capability_excess).is_err());

    let mut unknown_dependency = fixture.request.clone();
    unknown_dependency.canonical_specification_ref = id("spec:not-admitted");
    assert!(project(&fixture, unknown_dependency).is_err());

    let mut package_tamper = fixture.seed.clone();
    let package_ref = fixture.catalogue.generation.packages[0].package_id.clone();
    package_tamper.dependency_roots.remove(&package_ref);
    package_tamper.seed_digest = sop_seed_digest(&package_tamper).expect("changed seed hashes");
    assert!(
        project_provider_free_self_ordering(
            &package_tamper,
            &fixture.fabric,
            &fixture.catalogue,
            &fixture.index,
            &fixture.lookup_request,
            &fixture.lookup_result,
            &fixture.source_budget,
            &fixture.source_projection,
            fixture.request.clone(),
        )
        .is_err()
    );

    let mut duplicate_source = fixture.request.clone();
    duplicate_source.node_directives[1].source_unit_ref =
        duplicate_source.node_directives[0].source_unit_ref.clone();
    assert!(project(&fixture, duplicate_source).is_err());

    let mut missing_type = fixture.request.clone();
    missing_type.node_directives[0].type_ref = None;
    assert!(project(&fixture, missing_type).is_err());

    let mut source_tamper = fixture.source_projection.clone();
    source_tamper.proof_digest.value.replace_range(0..1, "f");
    assert!(
        project_provider_free_self_ordering(
            &fixture.seed,
            &fixture.fabric,
            &fixture.catalogue,
            &fixture.index,
            &fixture.lookup_request,
            &fixture.lookup_result,
            &fixture.source_budget,
            &source_tamper,
            fixture.request.clone(),
        )
        .is_err()
    );

    let mut backend_tamper = projection;
    backend_tamper.plan.backend_profile = "backend:substituted".to_owned();
    assert!(validate(&fixture, &backend_tamper).is_err());

    let mut request_json = serde_json::to_value(&fixture.request).expect("request serializes");
    request_json["undeclared"] = json!(true);
    assert!(serde_json::from_value::<SelfOrderingRequest>(request_json).is_err());
}

fn project(
    fixture: &Fixture,
    request: SelfOrderingRequest,
) -> cantor_core::SemanticCompilerValidation<cantor_core::ProviderFreeSelfOrderingProjection> {
    project_provider_free_self_ordering(
        &fixture.seed,
        &fixture.fabric,
        &fixture.catalogue,
        &fixture.index,
        &fixture.lookup_request,
        &fixture.lookup_result,
        &fixture.source_budget,
        &fixture.source_projection,
        request,
    )
}

fn validate(
    fixture: &Fixture,
    projection: &cantor_core::ProviderFreeSelfOrderingProjection,
) -> cantor_core::SemanticCompilerValidation {
    validate_provider_free_self_ordering_projection(
        &fixture.seed,
        &fixture.fabric,
        &fixture.catalogue,
        &fixture.index,
        &fixture.lookup_request,
        &fixture.lookup_result,
        &fixture.source_budget,
        &fixture.source_projection,
        &fixture.request,
        projection,
    )
}

fn fixture() -> Fixture {
    let root = workspace_root();
    let manifest_path = root.join("corpus/self_hosted/corpus.json");
    let manifest_bytes = fs::read(&manifest_path).expect("tracked corpus manifest reads");
    let manifest: SopCorpusManifest =
        serde_json::from_slice(&manifest_bytes).expect("tracked corpus manifest decodes");
    let source_root = manifest_path
        .parent()
        .expect("manifest has parent")
        .join(&manifest.source_root)
        .canonicalize()
        .expect("source root exists");
    let documents = manifest
        .documents
        .iter()
        .map(|document| SopDocumentInput {
            document_id: document.document_id.clone(),
            path: document.path.clone(),
            bytes: fs::read(source_root.join(&document.path)).expect("governed source reads"),
        })
        .collect();
    let built = build_sop_corpus(
        &manifest,
        documents,
        SopSigningKeys {
            authority: SigningKey::from_bytes(&[41_u8; 32]),
            compiler: SigningKey::from_bytes(&[43_u8; 32]),
        },
    )
    .expect("tracked corpus builds");
    let mut admitted = Vec::new();
    for package in &built.environment.packages {
        let certificate = package.certificate.as_ref().expect("package is certified");
        admitted.push(
            admit_package(
                package,
                &built.environment.trust_store,
                &certificate.authority_scope,
                built.environment.now_epoch_seconds,
            )
            .expect("package admits"),
        );
    }
    let fabric = SemanticFabric::from_admitted(admitted).expect("fabric derives");
    let catalogue = derive_semantic_anchor_catalogue(
        &fabric,
        CatalogueDerivationRequest {
            catalogue_id: id("catalogue:self-ordering-fixture"),
            logical_revision: "self-ordering-fixture/0.1".to_owned(),
        },
    )
    .expect("catalogue derives");
    let index = derive_lexical_association_index(
        &fabric,
        &catalogue,
        LexicalIndexDerivationRequest {
            index_id: id("lexical-index:self-ordering-fixture"),
            logical_revision: "self-ordering-fixture/0.1".to_owned(),
            tokenizer_profile: LEXICAL_TOKENIZER_PROFILE.to_owned(),
        },
    )
    .expect("index derives");
    let lookup_request = LexicalAnchorLookupRequest {
        profile: LEXICAL_ANCHOR_LOOKUP_PROFILE.to_owned(),
        request_id: id("request:self-ordering-fixture-lookup"),
        terms: vec![
            "Cantor".to_owned(),
            "SemanticUnit".to_owned(),
            "PreparedRuntime".to_owned(),
        ],
        budget: LexicalAnchorLookupBudget {
            maximum_terms: 8,
            maximum_query_bytes: 4096,
            maximum_unique_tokens: 64,
            maximum_postings: 4096,
            maximum_matches: 256,
            maximum_serialized_result_bytes: 4 * 1024 * 1024,
        },
    };
    let lookup_result = lookup_lexical_anchors(&fabric, &catalogue, &index, lookup_request.clone())
        .expect("lookup succeeds");
    let source_budget = LexicalAnchorSourceProjectionBudget {
        maximum_projections: 256,
        maximum_quote_bytes: 1024 * 1024,
        maximum_serialized_result_bytes: 4 * 1024 * 1024,
    };
    let source_projection = project_lexical_anchor_sources(
        &fabric,
        &catalogue,
        &index,
        &lookup_request,
        &lookup_result,
        source_budget.clone(),
    )
    .expect("source projection succeeds");

    let cantor_unit = projected_unit(&source_projection, "+ [Cantor]");
    let semantic_unit = projected_unit(&source_projection, "& [SemanticUnit]");
    let prepared_runtime = projected_unit(&source_projection, "& [PreparedRuntime]");
    let source_manifest_ref = id("source:tracked-self-hosted-corpus-manifest");
    let canonical_specification_ref = id("spec:seeded-multi-backend-compiler");
    let canonical_bytes =
        fs::read(root.join("specifications/Cantor_SOP_Seeded_Multi_Backend_Compiler_P0.sop"))
            .expect("canonical specification reads");
    let seed = seed(
        source_manifest_ref.clone(),
        digest(&manifest_bytes),
        canonical_specification_ref.clone(),
        digest(&canonical_bytes),
        catalogue
            .generation
            .packages
            .iter()
            .map(|package| (package.package_id.clone(), package.package_digest.clone()))
            .collect(),
    );
    let type_node = id("node:type-cantor");
    let input_node = id("node:input-semantic-unit");
    let output_node = id("node:output-prepared-runtime");
    let mut node_directives = vec![
        SelfOrderingNodeDirective {
            source_unit_ref: semantic_unit,
            node_id: input_node.clone(),
            kind: SemanticIrNodeKind::Input,
            type_ref: Some(type_node.clone()),
            dependency_refs: BTreeSet::from([type_node.clone()]),
        },
        SelfOrderingNodeDirective {
            source_unit_ref: prepared_runtime,
            node_id: output_node,
            kind: SemanticIrNodeKind::Output,
            type_ref: Some(type_node.clone()),
            dependency_refs: BTreeSet::from([input_node, type_node.clone()]),
        },
        SelfOrderingNodeDirective {
            source_unit_ref: cantor_unit,
            node_id: type_node,
            kind: SemanticIrNodeKind::Type,
            type_ref: None,
            dependency_refs: BTreeSet::new(),
        },
    ];
    node_directives.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let request = SelfOrderingRequest {
        profile: SELF_ORDERING_REQUEST_PROFILE.to_owned(),
        request_id: id("request:provider-free-self-ordering"),
        source_manifest_ref,
        canonical_specification_ref,
        purpose: PURPOSE.to_owned(),
        backend: CompilerBackendKind::AttentionProcedure,
        requested_capabilities: BTreeSet::from([CompilerCapability::SemanticRead]),
        node_directives,
        verifier_refs: BTreeSet::from([
            id("proof:lexical-anchor-lookup"),
            id("proof:signed-source-projection"),
        ]),
        rollback_ref: id("generation:cantor-current"),
        unresolved_account: BTreeSet::from([
            "semantic roles are explicit fixture directives, not lexically inferred".to_owned(),
        ]),
    };

    Fixture {
        seed,
        fabric,
        catalogue,
        index,
        lookup_request,
        lookup_result,
        source_budget,
        source_projection,
        request,
    }
}

fn seed(
    source_manifest_ref: SemanticId,
    source_manifest_digest: ContentDigest,
    canonical_specification_ref: SemanticId,
    canonical_specification_digest: ContentDigest,
    mut admitted_package_roots: BTreeMap<SemanticId, ContentDigest>,
) -> SopSeed {
    let mut ceiling = CompilerCapabilityCeiling {
        profile: COMPILER_CAPABILITY_CEILING_PROFILE.to_owned(),
        ceiling_id: id("ceiling:self-ordering-fixture"),
        capabilities: BTreeSet::from([
            CompilerCapability::SemanticRead,
            CompilerCapability::SourceRead,
        ]),
        resource_scopes: BTreeSet::from(["corpus:self_hosted".to_owned()]),
        maximum_artifacts: 1,
        maximum_serialized_bytes: 4 * 1024 * 1024,
        ceiling_digest: zero_digest(),
    };
    ceiling.ceiling_digest = compiler_capability_ceiling_digest(&ceiling).expect("ceiling hashes");
    admitted_package_roots.insert(source_manifest_ref, source_manifest_digest);
    admitted_package_roots.insert(canonical_specification_ref, canonical_specification_digest);
    let mut seed = SopSeed {
        profile: SOP_SEED_PROFILE.to_owned(),
        seed_id: id("seed:self-ordering-fixture"),
        generation_id: id("generation:cantor-current"),
        purpose: PURPOSE.to_owned(),
        honesty_trust_root_ref: id("trust:honesty"),
        security_trust_root_ref: id("trust:security"),
        authority_trust_root_ref: id("trust:authority"),
        compiler_trust_root_ref: id("trust:compiler"),
        dependency_roots: admitted_package_roots,
        discovery_contract_ref: id("contract:proof-bearing-catalogue-discovery"),
        semantic_frontend_profile: "compiler:semantic-front-end/0.1".to_owned(),
        backend_profiles: BTreeMap::from([
            (
                CompilerBackendKind::AttentionProcedure,
                "backend:attention-procedure/0.1".to_owned(),
            ),
            (
                CompilerBackendKind::InferenceHostIntegration,
                "backend:inference-host-integration/0.1".to_owned(),
            ),
            (
                CompilerBackendKind::NativeArtifact,
                "backend:native-artifact/0.1".to_owned(),
            ),
        ]),
        capability_ceiling: ceiling,
        predecessor_generation_ref: None,
        successor_policy_ref: id("policy:external-successor-recognition"),
        seed_digest: zero_digest(),
    };
    seed.seed_digest = sop_seed_digest(&seed).expect("seed hashes");
    seed
}

fn projected_unit(
    projection: &cantor_core::LexicalAnchorSourceProjectionResult,
    prefix: &str,
) -> SemanticId {
    projection
        .projections
        .iter()
        .find(|entry| entry.text.starts_with(prefix))
        .unwrap_or_else(|| panic!("tracked corpus must project {prefix}"))
        .address
        .unit_id
        .clone()
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn zero_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: "0".repeat(64),
    }
}

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture semantic identity is valid")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core crate is nested under workspace root")
        .to_path_buf()
}
