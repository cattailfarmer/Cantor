use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use cantor_core::{
    AuthorityContext, AuthorityScope, CantorQueryRequest, EMBEDDED_ENVIRONMENT_VERSION,
    EmbeddedRuntimeEnvironment, ExitClass, ExpectedPackage, InspectRequest, PROTOCOL_VERSION,
    PackageCompilationInput, PackageCompiler, ProtocolCallerContext, ProtocolOperation,
    ProtocolOutcome, ProtocolRequest, ProtocolResponse, QUERY_PROTOCOL_VERSION, QueryBudget,
    RequestedDetailKind, SearchMode, SemanticContext, SemanticId, SemanticUnit, SignerRole,
    SourceDocumentInput, TrustStore, TrustedSignerRecord, UnitCompilationInput, UnitKind,
    UnitStatus, embedded_environment_digest, execute_protocol_request, verify_protocol_response,
    verify_protocol_response_against_environment,
};
use ed25519_dalek::SigningKey;
use serde_json::json;

use cantor_mcp::CantorMcpServer;

const NOW: u64 = 120;
static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("static CLI fixture identity must be valid")
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        projects: ["cantor".to_owned()].into_iter().collect(),
        namespaces: ["cli".to_owned()].into_iter().collect(),
        semantic_kinds: [UnitKind::Term].into_iter().collect(),
        perspectives: ["fixture".to_owned()].into_iter().collect(),
        instruction_capabilities: ["read".to_owned()].into_iter().collect(),
    }
}

fn dependency_lock() -> BTreeMap<String, String> {
    [("cantor-cli-fixture".to_owned(), "1".to_owned())]
        .into_iter()
        .collect()
}

fn fixture(term: &str, operation: &str) -> (EmbeddedRuntimeEnvironment, ProtocolRequest) {
    let compiler = PackageCompiler::new(
        id("compiler:cli_fixture"),
        "1.0.0",
        id("signer:cli_authority"),
        id("signer:cli_compiler"),
        SigningKey::from_bytes(&[23_u8; 32]),
        SigningKey::from_bytes(&[29_u8; 32]),
    );
    let clause = "& [cantor] is a signed semantic coprocessor";
    let unit = SemanticUnit {
        unit_id: id("unit:cantor"),
        kind: UnitKind::Term,
        expression: "cantor".to_owned(),
        aliases: ["semantic coprocessor".to_owned()].into_iter().collect(),
        meaning: "a signed semantic coprocessor".to_owned(),
        context: SemanticContext::fixture("cli", "resolve CLI fixture"),
        source_set: vec!["fixture:cli".to_owned()],
        status: UnitStatus::Asserted,
    };
    let package = compiler
        .compile(PackageCompilationInput {
            sources: vec![SourceDocumentInput {
                file_id: id("file:cli_fixture"),
                path: "fixtures/cli.sop".to_owned(),
                bytes: clause.as_bytes().to_vec(),
            }],
            units: vec![UnitCompilationInput {
                unit,
                file_id: id("file:cli_fixture"),
                clause_id: id("clause:cli_fixture"),
                byte_start: 0,
                byte_end: clause.len(),
            }],
            relations: Vec::new(),
            dependency_lock: dependency_lock(),
            authority_scope: scope(),
            proof_ids: vec!["proof:cli_fixture".to_owned()],
            issued_at_epoch_seconds: 100,
            not_before_epoch_seconds: 90,
            not_after_epoch_seconds: 200,
        })
        .expect("CLI fixture package must compile");
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
    let request_id = id("request:cli_fixture");
    let caller_id = id("caller:cli_fixture");
    let purpose = "resolve CLI fixture";
    let request = match operation {
        "query" => ProtocolOperation::Query {
            query: Box::new(CantorQueryRequest {
                protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
                request_id: request_id.clone(),
                term_set: [term.to_owned()].into_iter().collect(),
                subject: Some("cli".to_owned()),
                purpose: purpose.to_owned(),
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
                source_scopes: ["cli".to_owned()].into_iter().collect(),
                perspectives: BTreeSet::new(),
                known_units: BTreeSet::new(),
                authority_context: AuthorityContext {
                    caller_id: caller_id.clone(),
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
        "inspect" => ProtocolOperation::Inspect {
            inspect: InspectRequest::Fabric,
        },
        _ => panic!("unsupported fixture operation"),
    };
    let expected_package = ExpectedPackage {
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
        trust_store,
        packages: vec![package],
    };
    let request = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id,
        caller_context: ProtocolCallerContext {
            caller_id,
            purpose: purpose.to_owned(),
            job_id: Some(id("job:cli_fixture")),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: embedded_environment_digest(&environment)
            .expect("fixture environment must encode"),
        expected_packages: vec![expected_package],
        requested_scope: scope(),
        request,
    };
    (environment, request)
}

fn temporary_path(label: &str) -> std::path::PathBuf {
    let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cantor-cli-test-{}-{sequence}-{label}.json",
        std::process::id()
    ))
}

fn run_cli(command: &str, environment: &EmbeddedRuntimeEnvironment, input: &[u8]) -> Output {
    let environment_path = temporary_path("environment");
    std::fs::write(
        &environment_path,
        serde_json::to_vec(environment).expect("environment must encode"),
    )
    .expect("temporary environment must be written");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cantor"))
        .arg(command)
        .arg("--environment")
        .arg(&environment_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Cantor CLI must start");
    child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(input)
        .expect("request must be written");
    let output = child.wait_with_output().expect("Cantor CLI must finish");
    std::fs::remove_file(&environment_path).expect("temporary environment must be removed");
    output
}

fn response(output: &Output) -> ProtocolResponse {
    serde_json::from_slice(&output.stdout).expect("stdout must contain exactly one JSON response")
}

#[test]
fn query_subprocess_is_machine_clean_and_core_equivalent() {
    let (environment, request) = fixture("cantor", "query");
    let direct = execute_protocol_request(&environment, request.clone());
    let bytes = serde_json::to_vec(&request).expect("request must encode");
    let output = run_cli("query", &environment, &bytes);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let parsed = response(&output);
    assert_eq!(parsed, direct);
    verify_protocol_response(&request, &parsed).expect("subprocess query response must verify");
    verify_protocol_response_against_environment(&environment, &request, &parsed)
        .expect("subprocess query must equal pinned-environment execution");
    assert_eq!(output.stdout.last(), Some(&b'\n'));
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
}

#[test]
fn inspect_subprocess_is_core_equivalent_and_repeatable() {
    let (environment, request) = fixture("cantor", "inspect");
    let bytes = serde_json::to_vec(&request).expect("request must encode");
    let first = run_cli("inspect", &environment, &bytes);
    let second = run_cli("inspect", &environment, &bytes);

    assert_eq!(first.status.code(), Some(0));
    verify_protocol_response(&request, &response(&first))
        .expect("subprocess inspect response must verify");
    verify_protocol_response_against_environment(&environment, &request, &response(&first))
        .expect("subprocess inspection must equal pinned-environment execution");
    assert!(matches!(
        response(&first).result,
        ProtocolOutcome::Inspect(_)
    ));
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn malformed_json_and_command_mismatch_return_json_and_exit_two() {
    let (environment, _) = fixture("cantor", "query");
    let malformed = run_cli("query", &environment, b"{not json");
    assert_eq!(
        malformed.status.code(),
        Some(i32::from(ExitClass::InvalidRequest.code()))
    );
    assert!(!malformed.stderr.is_empty());
    assert_eq!(response(&malformed).exit_class, ExitClass::InvalidRequest);

    let (environment, inspect_request) = fixture("cantor", "inspect");
    let mismatch = run_cli(
        "query",
        &environment,
        &serde_json::to_vec(&inspect_request).expect("request must encode"),
    );
    assert_eq!(mismatch.status.code(), Some(2));
    assert_eq!(
        response(&mismatch).faults[0].code,
        "operation_command_mismatch"
    );

    let (environment, request) = fixture("cantor", "query");
    let mut invalid_identity = serde_json::to_value(request).expect("request must encode");
    invalid_identity["request_id"] = serde_json::Value::String("invalid identity".to_owned());
    let output = run_cli(
        "query",
        &environment,
        &serde_json::to_vec(&invalid_identity).expect("invalid fixture JSON must encode"),
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(response(&output).faults[0].code, "malformed_json");
}

#[test]
fn trust_unresolved_policy_and_semantic_exit_classes_preserve_results() {
    let (mut environment, trust) = fixture("cantor", "query");
    environment.packages[0].content.sources[0].bytes[0] ^= 1;
    let mut trust = trust;
    trust.expected_environment_digest =
        embedded_environment_digest(&environment).expect("fixture environment must encode");
    let output = run_cli(
        "query",
        &environment,
        &serde_json::to_vec(&trust).expect("request must encode"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(response(&output).exit_class, ExitClass::TrustFailure);

    let (environment, unknown) = fixture("not-represented", "query");
    let output = run_cli(
        "query",
        &environment,
        &serde_json::to_vec(&unknown).expect("request must encode"),
    );
    assert_eq!(output.status.code(), Some(4));
    assert!(matches!(
        response(&output).result,
        ProtocolOutcome::Query(_)
    ));

    let (environment, mut policy) = fixture("cantor", "query");
    if let ProtocolOperation::Query { query } = &mut policy.request {
        query.authority_context.allowed_package_scopes =
            ["unrelated".to_owned()].into_iter().collect();
    }
    let output = run_cli(
        "query",
        &environment,
        &serde_json::to_vec(&policy).expect("request must encode"),
    );
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(response(&output).exit_class, ExitClass::PolicyDenial);

    let (environment, mut budget) = fixture("cantor", "query");
    if let ProtocolOperation::Query { query } = &mut budget.request {
        query.budget.maximum_bytes = 1;
    }
    let output = run_cli(
        "query",
        &environment,
        &serde_json::to_vec(&budget).expect("request must encode"),
    );
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(response(&output).exit_class, ExitClass::SemanticFault);
}

#[test]
fn explicit_input_file_uses_the_same_protocol() {
    let (environment, request) = fixture("cantor", "inspect");
    let path = temporary_path("request");
    let environment_path = temporary_path("environment");
    std::fs::write(
        &path,
        serde_json::to_vec(&request).expect("request must encode"),
    )
    .expect("temporary request file must be written");
    std::fs::write(
        &environment_path,
        serde_json::to_vec(&environment).expect("environment must encode"),
    )
    .expect("temporary environment file must be written");
    let output = Command::new(env!("CARGO_BIN_EXE_cantor"))
        .arg("inspect")
        .arg("--environment")
        .arg(&environment_path)
        .arg("--input")
        .arg(&path)
        .output()
        .expect("Cantor CLI must finish");
    std::fs::remove_file(&path).expect("temporary request file must be removed");
    std::fs::remove_file(&environment_path).expect("temporary environment file must be removed");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        response(&output),
        execute_protocol_request(&environment, request)
    );
}

#[test]
fn cli_and_mcp_adapter_return_the_same_protocol_response() {
    let (environment, request) = fixture("cantor", "query");
    let cli_output = run_cli(
        "query",
        &environment,
        &serde_json::to_vec(&request).expect("request must encode"),
    );
    assert_eq!(cli_output.status.code(), Some(0));

    let server =
        CantorMcpServer::new(environment).expect("the signed fixture must pass MCP preflight");
    let arguments = json!({ "request": request })
        .as_object()
        .expect("tool arguments must be an object")
        .clone();
    let mcp_result = server.execute_tool_arguments(Some(arguments));
    let mcp_response: ProtocolResponse = serde_json::from_value(
        mcp_result
            .structured_content
            .expect("MCP result must carry structured content"),
    )
    .expect("MCP structured content must be a ProtocolResponse");

    assert_eq!(mcp_result.is_error, Some(false));
    assert_eq!(response(&cli_output), mcp_response);
}
