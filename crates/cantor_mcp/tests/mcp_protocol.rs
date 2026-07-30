use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};

use cantor_core::{
    AuthorityContext, AuthorityScope, CantorQueryRequest, EMBEDDED_ENVIRONMENT_VERSION,
    EmbeddedRuntimeEnvironment, ExitClass, ExpectedPackage, PROTOCOL_VERSION,
    PackageCompilationInput, PackageCompiler, ProtocolCallerContext, ProtocolOperation,
    ProtocolRequest, ProtocolResponse, QUERY_PROTOCOL_VERSION, QueryBudget, RequestedDetailKind,
    SearchMode, SemanticContext, SemanticId, SemanticUnit, SignerRole, SourceDocumentInput,
    TrustStore, TrustedSignerRecord, UnitCompilationInput, UnitKind, UnitStatus,
    embedded_environment_digest, execute_protocol_request,
    verify_protocol_response_against_environment,
};
use cantor_mcp::{CantorMcpServer, MAX_ARGUMENT_BYTES, TOOL_NAME};
use ed25519_dalek::SigningKey;
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::json;

const NOW: u64 = 120;
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("static MCP fixture identity must be valid")
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        projects: ["cantor".to_owned()].into_iter().collect(),
        namespaces: ["mcp".to_owned()].into_iter().collect(),
        semantic_kinds: [UnitKind::Term].into_iter().collect(),
        perspectives: ["fixture".to_owned()].into_iter().collect(),
        instruction_capabilities: ["read".to_owned()].into_iter().collect(),
    }
}

fn dependency_lock() -> BTreeMap<String, String> {
    [("cantor-mcp-fixture".to_owned(), "1".to_owned())]
        .into_iter()
        .collect()
}

fn fixture(term: &str) -> (EmbeddedRuntimeEnvironment, ProtocolRequest) {
    let compiler = PackageCompiler::new(
        id("compiler:mcp_fixture"),
        "1.0.0",
        id("signer:mcp_authority"),
        id("signer:mcp_compiler"),
        SigningKey::from_bytes(&[31_u8; 32]),
        SigningKey::from_bytes(&[37_u8; 32]),
    );
    let clause = "& [cantor] is a signed semantic coprocessor";
    let unit = SemanticUnit {
        unit_id: id("unit:cantor"),
        kind: UnitKind::Term,
        expression: "cantor".to_owned(),
        aliases: ["semantic coprocessor".to_owned()].into_iter().collect(),
        meaning: "a signed semantic coprocessor".to_owned(),
        context: SemanticContext::fixture("mcp", "resolve MCP fixture"),
        source_set: vec!["fixture:mcp".to_owned()],
        status: UnitStatus::Asserted,
    };
    let package = compiler
        .compile(PackageCompilationInput {
            sources: vec![SourceDocumentInput {
                file_id: id("file:mcp_fixture"),
                path: "fixtures/mcp.sop".to_owned(),
                bytes: clause.as_bytes().to_vec(),
            }],
            units: vec![UnitCompilationInput {
                unit,
                file_id: id("file:mcp_fixture"),
                clause_id: id("clause:mcp_fixture"),
                byte_start: 0,
                byte_end: clause.len(),
            }],
            relations: Vec::new(),
            dependency_lock: dependency_lock(),
            authority_scope: scope(),
            proof_ids: vec!["proof:mcp_fixture".to_owned()],
            issued_at_epoch_seconds: 100,
            not_before_epoch_seconds: 90,
            not_after_epoch_seconds: 200,
        })
        .expect("MCP fixture package must compile");
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
    let request_id = id("request:mcp_fixture");
    let caller_id = id("caller:mcp_fixture");
    let request = ProtocolRequest {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        request_id: request_id.clone(),
        caller_context: ProtocolCallerContext {
            caller_id: caller_id.clone(),
            purpose: "resolve MCP fixture".to_owned(),
            job_id: Some(id("job:mcp_fixture")),
            effect_boundary: "read_only".to_owned(),
        },
        expected_environment_digest: embedded_environment_digest(&environment)
            .expect("fixture environment must encode"),
        expected_packages: vec![expected_package],
        requested_scope: scope(),
        request: ProtocolOperation::Query {
            query: Box::new(CantorQueryRequest {
                protocol_version: QUERY_PROTOCOL_VERSION.to_owned(),
                request_id,
                term_set: [term.to_owned()].into_iter().collect(),
                subject: Some("mcp".to_owned()),
                purpose: "resolve MCP fixture".to_owned(),
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
                source_scopes: ["mcp".to_owned()].into_iter().collect(),
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
    (environment, request)
}

fn tool_arguments(request: &ProtocolRequest) -> serde_json::Map<String, serde_json::Value> {
    json!({ "request": request })
        .as_object()
        .expect("tool arguments must be an object")
        .clone()
}

fn structured_response(result: &rmcp::model::CallToolResult) -> ProtocolResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("tool result must carry structured content"),
    )
    .expect("structured content must be a ProtocolResponse")
}

#[test]
fn tool_metadata_declares_one_closed_read_only_operation() {
    let tool = CantorMcpServer::tool_definition();
    assert_eq!(tool.name, TOOL_NAME);
    assert!(tool.output_schema.is_some());
    let annotations = tool
        .annotations
        .as_ref()
        .expect("tool annotations are required");
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert_eq!(
        tool.input_schema.get("additionalProperties"),
        Some(&json!(false))
    );
    let metadata_bytes = serde_json::to_vec(&tool)
        .expect("tool metadata must encode")
        .len();
    assert!(
        metadata_bytes < 32_768,
        "tool discovery metadata must remain a bounded attention payload"
    );
}

#[test]
fn adapter_result_is_exactly_core_equivalent() {
    let (environment, request) = fixture("cantor");
    let direct = execute_protocol_request(&environment, request.clone());
    let server = CantorMcpServer::new(environment.clone()).expect("fixture must pass preflight");
    let result = server.execute_tool_arguments(Some(tool_arguments(&request)));

    assert_eq!(result.is_error, Some(false));
    let summary = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .expect("tool result must carry a concise text projection");
    assert!(summary.text.len() < 160);
    assert!(summary.text.contains("exit_class=success"));
    let response = structured_response(&result);
    assert_eq!(response, direct);
    verify_protocol_response_against_environment(&environment, &request, &response)
        .expect("MCP projection must equal pinned core execution");

    let second = server.execute_tool_arguments(Some(tool_arguments(&request)));
    assert_eq!(structured_response(&second), direct);
    let metrics = server.runtime().metrics();
    assert_eq!(metrics.projection_preparations, 1);
    assert_eq!(metrics.projection_hits, 1);
}

#[test]
fn malformed_arguments_are_visible_structured_tool_faults() {
    let (environment, _) = fixture("cantor");
    let server = CantorMcpServer::new(environment).expect("fixture must pass preflight");
    let result = server.execute_tool_arguments(Some(
        json!({ "request": {}, "unexpected": true })
            .as_object()
            .expect("fixture arguments are an object")
            .clone(),
    ));

    assert_eq!(result.is_error, Some(true));
    let content = result
        .structured_content
        .expect("adapter fault must be structured");
    assert_eq!(content["status"], "fault");
    assert_eq!(content["fault"]["code"], "invalid_arguments");
}

#[test]
fn oversized_arguments_fail_before_protocol_decoding() {
    let (environment, _) = fixture("cantor");
    let server = CantorMcpServer::new(environment).expect("fixture must pass preflight");
    let result = server.execute_tool_arguments(Some(
        json!({ "padding": "x".repeat(MAX_ARGUMENT_BYTES) })
            .as_object()
            .expect("fixture arguments are an object")
            .clone(),
    ));

    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result
            .structured_content
            .expect("adapter fault must be structured")["fault"]["code"],
        "argument_limit_exceeded"
    );
}

#[test]
fn startup_rejects_a_package_changed_after_signing() {
    let (mut environment, _) = fixture("cantor");
    environment.packages[0].content.sources[0].bytes[0] ^= 1;
    let fault = CantorMcpServer::new(environment)
        .expect_err("changed signed content must fail startup preflight");

    assert_eq!(fault.code, "environment_package_rejected");
}

#[test]
fn trust_mismatch_remains_an_exact_protocol_fault() {
    let (environment, mut request) = fixture("cantor");
    request.expected_environment_digest.value = "00".repeat(32);
    let direct = execute_protocol_request(&environment, request.clone());
    assert_eq!(direct.exit_class, ExitClass::TrustFailure);
    let server = CantorMcpServer::new(environment).expect("fixture must pass preflight");
    let result = server.execute_tool_arguments(Some(tool_arguments(&request)));

    assert_eq!(result.is_error, Some(true));
    assert_eq!(structured_response(&result), direct);
}

#[tokio::test(flavor = "current_thread")]
async fn real_stdio_server_lists_and_executes_the_tool() {
    let (environment, request) = fixture("cantor");
    let direct = execute_protocol_request(&environment, request.clone());
    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "cantor-mcp-test-{}-{sequence}-environment.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        serde_json::to_vec(&environment).expect("environment must encode"),
    )
    .expect("temporary environment must be written");

    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-mcp")).configure(|command| {
            command.arg("--environment").arg(&path);
        }),
    )
    .expect("Cantor MCP subprocess must start");
    let client = ().serve(transport).await.expect("MCP initialization must pass");
    let tools = client
        .list_all_tools()
        .await
        .expect("tools/list must succeed");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);

    for _ in 0..25 {
        let result = client
            .call_tool(
                CallToolRequestParams::new(TOOL_NAME).with_arguments(tool_arguments(&request)),
            )
            .await
            .expect("repeated tools/call must succeed");
        assert_eq!(structured_response(&result), direct);
    }
    let malformed = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(
                json!({ "request": {} })
                    .as_object()
                    .expect("malformed fixture must be an object")
                    .clone(),
            ),
        )
        .await
        .expect("malformed tool input must remain a caller-visible result");
    assert_eq!(malformed.is_error, Some(true));
    let recovered = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(tool_arguments(&request)))
        .await
        .expect("server must remain healthy after a tool fault");
    assert_eq!(structured_response(&recovered), direct);
    client.cancel().await.expect("MCP client must stop");
    std::fs::remove_file(&path).expect("temporary environment must be removed");
}
