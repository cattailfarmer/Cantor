use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    AuthorityContext, AuthorityScope, CantorQueryRequest, EMBEDDED_ENVIRONMENT_VERSION,
    EmbeddedRuntimeEnvironment, ExpectedPackage, PROTOCOL_VERSION, PackageCompilationInput,
    PackageCompiler, ProtocolCallerContext, ProtocolOperation, ProtocolRequest,
    QUERY_PROTOCOL_VERSION, QueryBudget, RelationType, RequestedDetailKind, SearchMode,
    SemanticContext, SemanticId, SemanticRelation, SemanticUnit, SignerRole, SourceDocumentInput,
    TrustStore, TrustedSignerRecord, UnitCompilationInput, UnitKind, UnitStatus,
    embedded_environment_digest,
};
use ed25519_dalek::SigningKey;

pub const NOW: u64 = 120;

pub fn scope() -> AuthorityScope {
    AuthorityScope {
        projects: ["cantor".to_owned()].into_iter().collect(),
        namespaces: ["core".to_owned()].into_iter().collect(),
        semantic_kinds: [UnitKind::Term].into_iter().collect(),
        perspectives: ["fixture".to_owned()].into_iter().collect(),
        instruction_capabilities: ["read".to_owned()].into_iter().collect(),
    }
}

pub fn dependency_lock() -> BTreeMap<String, String> {
    [
        ("cantor-ir".to_owned(), "0.1".to_owned()),
        ("fixture-schema".to_owned(), "1".to_owned()),
    ]
    .into_iter()
    .collect()
}

pub fn compiler(version: &str) -> PackageCompiler {
    PackageCompiler::new(
        id("compiler:cantor_test"),
        version,
        id("signer:authority_test"),
        id("signer:compiler_test"),
        SigningKey::from_bytes(&[7_u8; 32]),
        SigningKey::from_bytes(&[11_u8; 32]),
    )
}

pub fn trust_store(
    trusted_compiler: &PackageCompiler,
    allowed_version: &str,
    authority_scope: &AuthorityScope,
) -> TrustStore {
    let mut store = TrustStore::empty(dependency_lock());
    store.signers.insert(
        trusted_compiler.authority_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: trusted_compiler.authority_signer_id.clone(),
            role: SignerRole::Authority,
            verifying_key: trusted_compiler.authority_verifying_key_bytes(),
            authority_scope: authority_scope.clone(),
            authorized_compiler_ids: BTreeSet::new(),
        },
    );
    store.signers.insert(
        trusted_compiler.compiler_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: trusted_compiler.compiler_signer_id.clone(),
            role: SignerRole::Compiler,
            verifying_key: trusted_compiler.compiler_verifying_key_bytes(),
            authority_scope: authority_scope.clone(),
            authorized_compiler_ids: [trusted_compiler.compiler_id.clone()].into_iter().collect(),
        },
    );
    store.allowed_compiler_versions.insert(
        trusted_compiler.compiler_id.clone(),
        [allowed_version.to_owned()].into_iter().collect(),
    );
    store
}

pub fn package_input(first_file_prefix: &str) -> PackageCompilationInput {
    let financial_clause = "& [bank_financial] is a financial institution";
    let river_clause = "& [bank_river] is land alongside a river";
    let first_text =
        format!("{first_file_prefix}{financial_clause}\n  + [use_case] is hold deposits\n");
    let second_text = format!("{river_clause}\n  + [boundary] is geography\n");
    let financial_start = first_text
        .find(financial_clause)
        .expect("fixture clause must be present");
    let river_start = second_text
        .find(river_clause)
        .expect("fixture clause must be present");
    let financial = unit(
        "unit:bank_financial",
        "bank",
        &["financial institution"],
        "an institution that receives deposits",
        "finance",
    );
    let river = unit(
        "unit:bank_river",
        "bank",
        &["riverbank"],
        "land alongside a river",
        "geography",
    );
    PackageCompilationInput {
        sources: vec![
            SourceDocumentInput {
                file_id: id("file:bank_financial"),
                path: "fixtures/bank_financial.sop".to_owned(),
                bytes: first_text.into_bytes(),
            },
            SourceDocumentInput {
                file_id: id("file:bank_river"),
                path: "fixtures/bank_river.sop".to_owned(),
                bytes: second_text.into_bytes(),
            },
        ],
        units: vec![
            UnitCompilationInput {
                unit: financial.clone(),
                file_id: id("file:bank_financial"),
                clause_id: id("clause:bank_financial_definition"),
                byte_start: financial_start,
                byte_end: financial_start + financial_clause.len(),
            },
            UnitCompilationInput {
                unit: river.clone(),
                file_id: id("file:bank_river"),
                clause_id: id("clause:bank_river_definition"),
                byte_start: river_start,
                byte_end: river_start + river_clause.len(),
            },
        ],
        relations: vec![SemanticRelation {
            relation_id: id("relation:bank_meanings_distinct"),
            source: financial.unit_id,
            relation_type: RelationType::DistinctFrom,
            target: river.unit_id,
            source_ref: "fixture:bank_pair".to_owned(),
        }],
        dependency_lock: dependency_lock(),
        authority_scope: scope(),
        proof_ids: vec!["proof:core_acceptance".to_owned()],
        issued_at_epoch_seconds: 100,
        not_before_epoch_seconds: 90,
        not_after_epoch_seconds: 200,
    }
}

pub fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture semantic identity must be valid")
}

#[allow(dead_code)]
pub fn query_request(term: &str) -> CantorQueryRequest {
    CantorQueryRequest {
        protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
        request_id: id("request:prepared_fixture"),
        term_set: [term.to_owned()].into_iter().collect(),
        subject: Some("finance".to_owned()),
        purpose: "resolve the intended meaning".to_owned(),
        use_case_set: BTreeSet::new(),
        include_boundary_set: BTreeSet::new(),
        exclude_boundary_set: BTreeSet::new(),
        description_need: None,
        requested_detail_kinds: [RequestedDetailKind::Term].into_iter().collect(),
        search_modes: [SearchMode::Exact, SearchMode::Contextual]
            .into_iter()
            .collect(),
        relation_types: BTreeSet::new(),
        criteria: BTreeSet::new(),
        source_scopes: ["finance".to_owned()].into_iter().collect(),
        perspectives: BTreeSet::new(),
        known_units: BTreeSet::new(),
        authority_context: AuthorityContext {
            caller_id: id("caller:prepared_fixture"),
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

#[allow(dead_code)]
pub fn protocol_fixture(
    operation: ProtocolOperation,
) -> (EmbeddedRuntimeEnvironment, ProtocolRequest) {
    let compiler = compiler("1.0.0");
    let package = compiler
        .compile(package_input(""))
        .expect("prepared runtime fixture package must compile");
    let expected = ExpectedPackage {
        package_id: package.package_id.clone(),
        package_digest: package
            .certificate
            .as_ref()
            .expect("fixture package is signed")
            .package_digest
            .clone(),
    };
    let environment = EmbeddedRuntimeEnvironment {
        environment_version: EMBEDDED_ENVIRONMENT_VERSION.to_owned(),
        now_epoch_seconds: NOW,
        trust_store: trust_store(&compiler, "1.0.0", &scope()),
        packages: vec![package],
    };
    let request = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: id("request:prepared_fixture"),
        caller_context: ProtocolCallerContext {
            caller_id: id("caller:prepared_fixture"),
            purpose: "resolve the intended meaning".to_owned(),
            job_id: Some(id("job:prepared_fixture")),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: embedded_environment_digest(&environment)
            .expect("fixture environment must encode"),
        expected_packages: vec![expected],
        requested_scope: scope(),
        request: operation,
    };
    (environment, request)
}

fn unit(
    unit_id: &str,
    expression: &str,
    aliases: &[&str],
    meaning: &str,
    scope: &str,
) -> SemanticUnit {
    SemanticUnit {
        unit_id: id(unit_id),
        kind: UnitKind::Term,
        expression: expression.to_owned(),
        aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
        meaning: meaning.to_owned(),
        context: SemanticContext::fixture(scope, "trusted-package fixture"),
        source_set: vec!["fixture:trusted_package".to_owned()],
        status: UnitStatus::Asserted,
    }
}
