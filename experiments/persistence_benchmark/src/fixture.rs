use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    AuthorityContext, AuthorityScope, CantorQueryRequest, EMBEDDED_ENVIRONMENT_VERSION,
    EmbeddedRuntimeEnvironment, ExpectedPackage, PROTOCOL_VERSION, PackageCompilationInput,
    PackageCompiler, ProtocolCallerContext, ProtocolOperation, ProtocolRequest,
    QUERY_PROTOCOL_VERSION, QueryBudget, RequestedDetailKind, SearchMode, SemanticContext,
    SemanticId, SemanticUnit, SignerRole, SourceDocumentInput, TrustStore, TrustedSignerRecord,
    UnitCompilationInput, UnitKind, UnitStatus, embedded_environment_digest,
};
use ed25519_dalek::SigningKey;

const NOW: u64 = 1_785_360_000;

pub fn build_fixture(
    package_count: usize,
) -> Result<(EmbeddedRuntimeEnvironment, ProtocolRequest), Box<dyn std::error::Error>> {
    let compiler = PackageCompiler::new(
        id("compiler:persistence_benchmark")?,
        "1.0.0",
        id("signer:persistence_authority")?,
        id("signer:persistence_compiler")?,
        SigningKey::from_bytes(&[61_u8; 32]),
        SigningKey::from_bytes(&[67_u8; 32]),
    );
    let mut packages = Vec::with_capacity(package_count);
    let mut expected_packages = Vec::with_capacity(package_count);
    for ordinal in 0..package_count {
        let source = format!("& [term-{ordinal}] is persistence benchmark semantic unit {ordinal}");
        let file_id = id(&format!("file:persistence:{ordinal}"))?;
        let package = compiler.compile(PackageCompilationInput {
            sources: vec![SourceDocumentInput {
                file_id: file_id.clone(),
                path: format!("fixtures/persistence/{ordinal}.sop"),
                bytes: source.as_bytes().to_vec(),
            }],
            units: vec![UnitCompilationInput {
                unit: SemanticUnit {
                    unit_id: id(&format!("unit:persistence:{ordinal}"))?,
                    kind: UnitKind::Term,
                    expression: format!("term-{ordinal}"),
                    aliases: [format!("benchmark-{ordinal}")].into_iter().collect(),
                    meaning: format!("persistence benchmark semantic unit {ordinal}"),
                    context: SemanticContext::fixture(
                        "persistence",
                        "compare physical reconstruction",
                    ),
                    source_set: vec!["fixture:persistence_benchmark".to_owned()],
                    status: UnitStatus::Asserted,
                },
                file_id,
                clause_id: id(&format!("clause:persistence:{ordinal}"))?,
                byte_start: 0,
                byte_end: source.len(),
            }],
            relations: Vec::new(),
            dependency_lock: dependency_lock(),
            authority_scope: scope(),
            proof_ids: vec![format!("proof:persistence:{ordinal}")],
            issued_at_epoch_seconds: NOW - 100,
            not_before_epoch_seconds: NOW - 200,
            not_after_epoch_seconds: NOW + 86_400,
        })?;
        expected_packages.push(ExpectedPackage {
            package_id: package.package_id.clone(),
            package_digest: package
                .certificate
                .as_ref()
                .ok_or("fixture compiler returned an unsigned package")?
                .package_digest
                .clone(),
        });
        packages.push(package);
    }

    let mut trust_store = TrustStore::empty(dependency_lock());
    trust_store.signers.insert(
        compiler.authority_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: compiler.authority_signer_id.clone(),
            role: SignerRole::Authority,
            verifying_key: compiler.authority_verifying_key_bytes(),
            authority_scope: scope(),
            authorized_compiler_ids: BTreeSet::new(),
        },
    );
    trust_store.signers.insert(
        compiler.compiler_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: compiler.compiler_signer_id.clone(),
            role: SignerRole::Compiler,
            verifying_key: compiler.compiler_verifying_key_bytes(),
            authority_scope: scope(),
            authorized_compiler_ids: [compiler.compiler_id.clone()].into_iter().collect(),
        },
    );
    trust_store.allowed_compiler_versions.insert(
        compiler.compiler_id.clone(),
        ["1.0.0".to_owned()].into_iter().collect(),
    );
    let environment = EmbeddedRuntimeEnvironment {
        environment_version: EMBEDDED_ENVIRONMENT_VERSION.to_owned(),
        now_epoch_seconds: NOW,
        trust_store,
        packages,
    };
    let request_id = id(&format!("request:persistence:{package_count}"))?;
    let caller_id = id("caller:persistence_benchmark")?;
    let request = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: request_id.clone(),
        caller_context: ProtocolCallerContext {
            caller_id: caller_id.clone(),
            purpose: "compare physical reconstruction".to_owned(),
            job_id: Some(id(&format!("job:persistence:{package_count}"))?),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: embedded_environment_digest(&environment)?,
        expected_packages,
        requested_scope: scope(),
        request: ProtocolOperation::Query {
            query: Box::new(CantorQueryRequest {
                protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
                request_id,
                term_set: [format!("term-{}", package_count - 1)]
                    .into_iter()
                    .collect(),
                subject: Some("persistence".to_owned()),
                purpose: "compare physical reconstruction".to_owned(),
                use_case_set: BTreeSet::new(),
                include_boundary_set: BTreeSet::new(),
                exclude_boundary_set: BTreeSet::new(),
                description_need: Some("persistence benchmark".to_owned()),
                requested_detail_kinds: [
                    RequestedDetailKind::Term,
                    RequestedDetailKind::SourceSpan,
                ]
                .into_iter()
                .collect(),
                search_modes: [SearchMode::Exact, SearchMode::Contextual]
                    .into_iter()
                    .collect(),
                relation_types: BTreeSet::new(),
                criteria: BTreeSet::new(),
                source_scopes: ["persistence".to_owned()].into_iter().collect(),
                perspectives: BTreeSet::new(),
                known_units: BTreeSet::new(),
                authority_context: AuthorityContext {
                    caller_id,
                    allowed_package_scopes: ["cantor".to_owned()].into_iter().collect(),
                    operation: "semantic_read".to_owned(),
                    effect_boundary: "read_only".to_owned(),
                },
                budget: QueryBudget {
                    maximum_records: 8,
                    maximum_paths: 8,
                    maximum_depth: 2,
                    maximum_bytes: 65_536,
                    maximum_elapsed_milliseconds: 10_000,
                },
            }),
        },
    };
    Ok((environment, request))
}

fn id(value: &str) -> Result<SemanticId, cantor_core::EvaluationFault> {
    SemanticId::new(value)
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        projects: ["cantor".to_owned()].into_iter().collect(),
        namespaces: ["persistence".to_owned()].into_iter().collect(),
        semantic_kinds: [UnitKind::Term].into_iter().collect(),
        perspectives: ["fixture".to_owned()].into_iter().collect(),
        instruction_capabilities: ["read".to_owned()].into_iter().collect(),
    }
}

fn dependency_lock() -> BTreeMap<String, String> {
    [("cantor-persistence-benchmark".to_owned(), "1".to_owned())]
        .into_iter()
        .collect()
}
