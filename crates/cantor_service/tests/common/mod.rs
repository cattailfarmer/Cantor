use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    AuthorityContext, AuthorityScope, CantorQueryRequest, EMBEDDED_ENVIRONMENT_VERSION,
    EmbeddedRuntimeEnvironment, ExpectedPackage, PROTOCOL_VERSION, PackageCompilationInput,
    PackageCompiler, ProtocolCallerContext, ProtocolOperation, ProtocolRequest,
    QUERY_PROTOCOL_VERSION, QueryBudget, RequestedDetailKind, SearchMode, SemanticContext,
    SemanticId, SemanticUnit, SignerRole, SourceDocumentInput, TrustStore, TrustedSignerRecord,
    UnitCompilationInput, UnitKind, UnitStatus, embedded_environment_digest, sha256_bytes,
};
use cantor_service::{
    ACTIVATION_SCHEMA, EnvironmentActivation, SERVICE_CONFIG_SCHEMA, ServiceConfig,
};
use ed25519_dalek::SigningKey;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub struct TestWorkspace {
    pub root: PathBuf,
    pub config_path: PathBuf,
    pub activation_path: PathBuf,
    pub token_path: PathBuf,
    pub environment_path: PathBuf,
}

impl TestWorkspace {
    pub fn new(now: u64, activation_sequence: u64) -> (Self, ProtocolRequest) {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cantor-service-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("test workspace must be created");
        let environment_path = root.join("environment.json");
        let activation_path = root.join("activation.json");
        let token_path = root.join("token.txt");
        let config_path = root.join("service.json");
        fs::write(&token_path, format!("{TOKEN}\n")).expect("token must write");
        let (environment, request) = protocol_fixture(now);
        publish_environment(
            &environment_path,
            &activation_path,
            &environment,
            activation_sequence,
        );
        let config = ServiceConfig {
            schema: SERVICE_CONFIG_SCHEMA.to_owned(),
            listen_address: "127.0.0.1:0".to_owned(),
            activation_path: activation_path.clone(),
            allowed_environment_root: root.clone(),
            auth_token_path: token_path.clone(),
            max_frame_bytes: 1024 * 1024,
            max_connections: 32,
            read_timeout_ms: 2_000,
            write_timeout_ms: 2_000,
        };
        write_json(&config_path, &config);
        (
            Self {
                root,
                config_path,
                activation_path,
                token_path,
                environment_path,
            },
            request,
        )
    }

    pub fn publish(&self, now: u64, sequence: u64) -> ProtocolRequest {
        let (environment, request) = protocol_fixture(now);
        publish_environment(
            &self.environment_path,
            &self.activation_path,
            &environment,
            sequence,
        );
        request
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn publish_environment(
    environment_path: &Path,
    activation_path: &Path,
    environment: &EmbeddedRuntimeEnvironment,
    sequence: u64,
) {
    let bytes = serde_json::to_vec(environment).expect("environment must encode");
    fs::write(environment_path, &bytes).expect("environment must write");
    let activation = EnvironmentActivation {
        schema: ACTIVATION_SCHEMA.to_owned(),
        sequence,
        environment_path: environment_path.to_owned(),
        environment_file_sha256: sha256_bytes(&bytes).value,
    };
    write_json(activation_path, &activation);
}

pub fn write_json(path: &Path, value: &impl serde::Serialize) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("fixture JSON must encode");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("fixture JSON must write");
}

pub fn protocol_fixture(now: u64) -> (EmbeddedRuntimeEnvironment, ProtocolRequest) {
    let compiler = compiler();
    let package = compiler
        .compile(package_input())
        .expect("service fixture package must compile");
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
        now_epoch_seconds: now,
        trust_store: trust_store(&compiler),
        packages: vec![package],
    };
    let request = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: id("request:service_fixture"),
        caller_context: ProtocolCallerContext {
            caller_id: id("caller:service_fixture"),
            purpose: "resolve the intended meaning".to_owned(),
            job_id: Some(id("job:service_fixture")),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: embedded_environment_digest(&environment)
            .expect("fixture environment must encode"),
        expected_packages: vec![expected],
        requested_scope: scope(),
        request: ProtocolOperation::Query {
            query: Box::new(query_request()),
        },
    };
    (environment, request)
}

pub fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity must be valid")
}

fn compiler() -> PackageCompiler {
    PackageCompiler::new(
        id("compiler:service_test"),
        "1.0.0",
        id("signer:service_authority"),
        id("signer:service_compiler"),
        SigningKey::from_bytes(&[31_u8; 32]),
        SigningKey::from_bytes(&[47_u8; 32]),
    )
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        projects: ["cantor".to_owned()].into_iter().collect(),
        namespaces: ["service".to_owned()].into_iter().collect(),
        semantic_kinds: [UnitKind::Term].into_iter().collect(),
        perspectives: ["fixture".to_owned()].into_iter().collect(),
        instruction_capabilities: ["read".to_owned()].into_iter().collect(),
    }
}

fn dependency_lock() -> BTreeMap<String, String> {
    [
        ("cantor-ir".to_owned(), "0.1".to_owned()),
        ("service-fixture".to_owned(), "1".to_owned()),
    ]
    .into_iter()
    .collect()
}

fn trust_store(compiler: &PackageCompiler) -> TrustStore {
    let authority_scope = scope();
    let mut store = TrustStore::empty(dependency_lock());
    store.signers.insert(
        compiler.authority_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: compiler.authority_signer_id.clone(),
            role: SignerRole::Authority,
            verifying_key: compiler.authority_verifying_key_bytes(),
            authority_scope: authority_scope.clone(),
            authorized_compiler_ids: BTreeSet::new(),
        },
    );
    store.signers.insert(
        compiler.compiler_signer_id.clone(),
        TrustedSignerRecord {
            signer_id: compiler.compiler_signer_id.clone(),
            role: SignerRole::Compiler,
            verifying_key: compiler.compiler_verifying_key_bytes(),
            authority_scope,
            authorized_compiler_ids: [compiler.compiler_id.clone()].into_iter().collect(),
        },
    );
    store.allowed_compiler_versions.insert(
        compiler.compiler_id.clone(),
        ["1.0.0".to_owned()].into_iter().collect(),
    );
    store
}

fn package_input() -> PackageCompilationInput {
    let clause = "& [cantor_service] is a resident semantic coprocessor";
    let source = format!("{clause}\n");
    let unit = SemanticUnit {
        unit_id: id("unit:cantor_service"),
        kind: UnitKind::Term,
        expression: "cantor service".to_owned(),
        aliases: ["cantord".to_owned()].into_iter().collect(),
        meaning: "a resident semantic coprocessor".to_owned(),
        context: SemanticContext::fixture("service", "resident service fixture"),
        source_set: vec!["fixture:service".to_owned()],
        status: UnitStatus::Asserted,
    };
    PackageCompilationInput {
        sources: vec![SourceDocumentInput {
            file_id: id("file:service_fixture"),
            path: "fixtures/service.sop".to_owned(),
            bytes: source.into_bytes(),
        }],
        units: vec![UnitCompilationInput {
            unit,
            file_id: id("file:service_fixture"),
            clause_id: id("clause:service_definition"),
            byte_start: 0,
            byte_end: clause.len(),
        }],
        relations: Vec::new(),
        dependency_lock: dependency_lock(),
        authority_scope: scope(),
        proof_ids: vec!["proof:service_fixture".to_owned()],
        issued_at_epoch_seconds: 100,
        not_before_epoch_seconds: 90,
        not_after_epoch_seconds: 10_000,
    }
}

fn query_request() -> CantorQueryRequest {
    CantorQueryRequest {
        protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
        request_id: id("request:service_query"),
        term_set: ["cantor service".to_owned()].into_iter().collect(),
        subject: Some("service".to_owned()),
        purpose: "resolve the resident service meaning".to_owned(),
        use_case_set: BTreeSet::new(),
        include_boundary_set: BTreeSet::new(),
        exclude_boundary_set: BTreeSet::new(),
        description_need: None,
        requested_detail_kinds: [RequestedDetailKind::Term].into_iter().collect(),
        search_modes: [SearchMode::Exact].into_iter().collect(),
        relation_types: BTreeSet::new(),
        criteria: BTreeSet::new(),
        source_scopes: ["service".to_owned()].into_iter().collect(),
        perspectives: BTreeSet::new(),
        known_units: BTreeSet::new(),
        authority_context: AuthorityContext {
            caller_id: id("caller:service_fixture"),
            allowed_package_scopes: ["cantor".to_owned()].into_iter().collect(),
            operation: "semantic_read".to_owned(),
            effect_boundary: "read_only".to_owned(),
        },
        budget: QueryBudget {
            maximum_records: 8,
            maximum_paths: 4,
            maximum_depth: 2,
            maximum_bytes: 16_384,
            maximum_elapsed_milliseconds: 1_000,
        },
    }
}
