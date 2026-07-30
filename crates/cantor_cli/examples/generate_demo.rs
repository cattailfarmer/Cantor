//! Generates a fixture-only embedded environment and matching protocol requests.
//! The fixed signing keys in this example are public test material and must
//! never be used as production authority.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use cantor_core::{
    AuthorityContext, AuthorityScope, CantorQueryRequest, EMBEDDED_ENVIRONMENT_VERSION,
    EmbeddedRuntimeEnvironment, ExpectedPackage, InspectRequest, PROTOCOL_VERSION,
    PackageCompilationInput, PackageCompiler, ProtocolCallerContext, ProtocolOperation,
    ProtocolRequest, QUERY_PROTOCOL_VERSION, QueryBudget, RequestedDetailKind, SearchMode,
    SemanticContext, SemanticId, SemanticUnit, SignerRole, SourceDocumentInput, TrustStore,
    TrustedSignerRecord, UnitCompilationInput, UnitKind, UnitStatus, embedded_environment_digest,
};
use ed25519_dalek::SigningKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: cargo run -p cantor_cli --example generate_demo -- <output-directory>")?;
    fs::create_dir_all(&output)?;

    let compiler = PackageCompiler::new(
        id("compiler:cantor_demo")?,
        "1.0.0",
        id("signer:demo_authority")?,
        id("signer:demo_compiler")?,
        SigningKey::from_bytes(&[41_u8; 32]),
        SigningKey::from_bytes(&[43_u8; 32]),
    );
    let source = "& [cantor] is a fixture-only signed semantic coprocessor";
    let package = compiler.compile(PackageCompilationInput {
        sources: vec![SourceDocumentInput {
            file_id: id("file:cantor_demo")?,
            path: "demo/cantor.sop".to_owned(),
            bytes: source.as_bytes().to_vec(),
        }],
        units: vec![UnitCompilationInput {
            unit: SemanticUnit {
                unit_id: id("unit:cantor_demo")?,
                kind: UnitKind::Term,
                expression: "cantor".to_owned(),
                aliases: ["semantic coprocessor".to_owned()].into_iter().collect(),
                meaning: "a fixture-only signed semantic coprocessor".to_owned(),
                context: SemanticContext::fixture("demo", "inspect Cantor demo"),
                source_set: vec!["fixture:generated_demo".to_owned()],
                status: UnitStatus::Asserted,
            },
            file_id: id("file:cantor_demo")?,
            clause_id: id("clause:cantor_demo")?,
            byte_start: 0,
            byte_end: source.len(),
        }],
        relations: Vec::new(),
        dependency_lock: dependency_lock(),
        authority_scope: scope(),
        proof_ids: vec!["proof:generated_demo".to_owned()],
        issued_at_epoch_seconds: 100,
        not_before_epoch_seconds: 0,
        not_after_epoch_seconds: 4_102_444_800,
    })?;
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
    let expected_package = ExpectedPackage {
        package_id: package.package_id.clone(),
        package_digest: package
            .certificate
            .as_ref()
            .ok_or("compiled demo package is unsigned")?
            .package_digest
            .clone(),
    };
    let environment = EmbeddedRuntimeEnvironment {
        environment_version: EMBEDDED_ENVIRONMENT_VERSION.to_owned(),
        now_epoch_seconds: 1_785_354_000,
        trust_store,
        packages: vec![package],
    };
    let environment_digest = embedded_environment_digest(&environment)?;
    let request_id = id("request:cantor_demo")?;
    let caller_id = id("caller:cantor_demo")?;
    let caller_context = ProtocolCallerContext {
        caller_id: caller_id.clone(),
        purpose: "inspect Cantor demo".to_owned(),
        job_id: Some(id("job:cantor_demo")?),
        effect_boundary: "read_only".to_owned(),
    };
    let query = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: request_id.clone(),
        caller_context: caller_context.clone(),
        expected_environment_digest: environment_digest.clone(),
        expected_packages: vec![expected_package.clone()],
        requested_scope: scope(),
        request: ProtocolOperation::Query {
            query: Box::new(CantorQueryRequest {
                protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
                request_id: request_id.clone(),
                term_set: ["cantor".to_owned()].into_iter().collect(),
                subject: Some("demo".to_owned()),
                purpose: caller_context.purpose.clone(),
                use_case_set: BTreeSet::new(),
                include_boundary_set: BTreeSet::new(),
                exclude_boundary_set: BTreeSet::new(),
                description_need: Some("semantic coprocessor".to_owned()),
                requested_detail_kinds: [
                    RequestedDetailKind::Term,
                    RequestedDetailKind::Definition,
                    RequestedDetailKind::SourceSpan,
                ]
                .into_iter()
                .collect(),
                search_modes: [SearchMode::Exact, SearchMode::Contextual]
                    .into_iter()
                    .collect(),
                relation_types: BTreeSet::new(),
                criteria: BTreeSet::new(),
                source_scopes: ["demo".to_owned()].into_iter().collect(),
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
                    maximum_bytes: 32_768,
                    maximum_elapsed_milliseconds: 1_000,
                },
            }),
        },
    };
    let inspect = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id,
        caller_context,
        expected_environment_digest: environment_digest,
        expected_packages: vec![expected_package],
        requested_scope: scope(),
        request: ProtocolOperation::Inspect {
            inspect: InspectRequest::Fabric,
        },
    };

    write_json(output.join("environment.json"), &environment)?;
    write_json(output.join("query.json"), &query)?;
    write_json(output.join("inspect.json"), &inspect)?;
    println!(
        "generated fixture-only Cantor protocol files in {}",
        output.display()
    );
    Ok(())
}

fn id(value: &str) -> Result<SemanticId, cantor_core::EvaluationFault> {
    SemanticId::new(value)
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        projects: ["cantor".to_owned()].into_iter().collect(),
        namespaces: ["demo".to_owned()].into_iter().collect(),
        semantic_kinds: [UnitKind::Term].into_iter().collect(),
        perspectives: ["fixture".to_owned()].into_iter().collect(),
        instruction_capabilities: ["read".to_owned()].into_iter().collect(),
    }
}

fn dependency_lock() -> BTreeMap<String, String> {
    [("cantor-demo".to_owned(), "1".to_owned())]
        .into_iter()
        .collect()
}

fn write_json(
    path: PathBuf,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}
