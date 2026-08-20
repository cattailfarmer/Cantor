use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
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
use cantor_mcp::{ANCHOR_TOOL_NAME, CantorMcpServer, MAX_ARGUMENT_BYTES, TOOL_NAME};
use cantor_service::{
    ACTIVATION_SCHEMA, BoundServer, EnvironmentActivation, SERVICE_CONFIG_SCHEMA, ServiceClient,
    ServiceConfig, ServiceDisposition, ServiceOperation, ServiceResult,
};
use ed25519_dalek::SigningKey;
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::json;

const NOW: u64 = 120;
const SERVICE_TOKEN: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
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

fn anchor_arguments(
    text: &str,
    include_source: Option<bool>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut value = json!({ "text": text });
    if let Some(include_source) = include_source {
        value["include_source"] = json!(include_source);
    }
    value
        .as_object()
        .expect("anchor tool arguments must be an object")
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
fn query_tool_metadata_declares_one_closed_read_only_operation() {
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
fn anchor_tool_metadata_is_small_strict_read_only_and_honest() {
    let tool = CantorMcpServer::anchor_tool_definition();
    assert_eq!(tool.name, ANCHOR_TOOL_NAME);
    assert!(tool.output_schema.is_some());
    assert_eq!(
        tool.input_schema.get("additionalProperties"),
        Some(&json!(false))
    );
    assert_eq!(
        tool.input_schema["properties"]["include_source"]["default"],
        json!(true)
    );
    let annotations = tool
        .annotations
        .as_ref()
        .expect("anchor annotations are required");
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert!(
        tool.description
            .as_deref()
            .is_some_and(|description| description.contains("not truth"))
    );
    assert!(serde_json::to_vec(&tool).unwrap().len() < 8_192);
}

#[test]
fn embedded_anchor_tool_returns_repeatable_lookup_and_exact_signed_source_by_default() {
    let (environment, _) = fixture("cantor");
    let server = CantorMcpServer::new(environment).expect("fixture must pass preflight");
    let arguments = anchor_arguments("Cantor", None);
    let first = server.execute_anchor_tool_arguments(Some(arguments.clone()));
    let second = server.execute_anchor_tool_arguments(Some(arguments));

    assert_eq!(first.is_error, Some(false));
    assert_eq!(first.structured_content, second.structured_content);
    let value = first
        .structured_content
        .expect("anchor lookup must return structured content");
    assert_eq!(value["status"], "success");
    assert_eq!(value["result"]["eligible_tokens"], json!(["cantor"]));
    assert_eq!(value["result"]["matches"].as_array().unwrap().len(), 1);
    assert_eq!(
        value["source_projection"]["lookup_proof_digest"],
        value["result"]["proof_digest"]
    );
    assert_eq!(
        value["source_projection"]["projections"][0]["source_path"],
        "fixtures/mcp.sop"
    );
    assert_eq!(
        value["source_projection"]["projections"][0]["text"],
        "& [cantor] is a signed semantic coprocessor"
    );
    assert!(
        value["result"]["non_authority_statement"]
            .as_str()
            .is_some_and(|statement| statement.contains("Lexical correspondence"))
    );
}

#[test]
fn anchor_tool_source_toggle_and_argument_faults_are_explicit() {
    let (environment, _) = fixture("cantor");
    let server = CantorMcpServer::new(environment).expect("fixture must pass preflight");
    let lexical_only = server
        .execute_anchor_tool_arguments(Some(anchor_arguments("Cantor", Some(false))))
        .structured_content
        .expect("lexical-only anchor lookup must be structured");
    assert!(lexical_only.get("source_projection").is_none());

    for arguments in [
        json!({ "text": "Cantor", "authority": true }),
        json!({ "text": "Cantor", "maximum_matches": 0 }),
        json!({ "text": " " }),
    ] {
        let result = server.execute_anchor_tool_arguments(Some(
            arguments
                .as_object()
                .expect("fault fixture must be an object")
                .clone(),
        ));
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result
                .structured_content
                .expect("anchor fault must be structured")["status"],
            "fault"
        );
    }
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
    let metrics = server
        .runtime()
        .expect("embedded MCP owns a PreparedRuntime")
        .metrics();
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
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, TOOL_NAME);
    assert_eq!(tools[1].name, ANCHOR_TOOL_NAME);

    let anchor = client
        .call_tool(
            CallToolRequestParams::new(ANCHOR_TOOL_NAME)
                .with_arguments(anchor_arguments("Cantor", None)),
        )
        .await
        .expect("anchor tools/call must succeed");
    assert_eq!(anchor.is_error, Some(false));
    assert_eq!(
        anchor
            .structured_content
            .expect("anchor process result must be structured")["source_projection"]["projections"]
            [0]["text"],
        "& [cantor] is a signed semantic coprocessor"
    );

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

#[test]
fn resident_backend_is_exact_pinned_and_visibly_unavailable() {
    let (environment, request) = fixture("cantor");
    let direct = execute_protocol_request(&environment, request.clone());
    let resident = LiveResident::start(&environment);
    let operator = ServiceClient::from_config(&resident.config_path)
        .expect("operator client must load before config mutation");
    assert!(!format!("{operator:?}").contains(SERVICE_TOKEN));
    let server = CantorMcpServer::from_service_config(&resident.config_path)
        .expect("resident-backed MCP must pass startup status");
    assert!(server.is_resident_backed());
    assert!(server.runtime().is_none());
    assert!(server.environment().is_none());
    let unavailable = server.execute_anchor_tool_arguments(Some(anchor_arguments("Cantor", None)));
    assert_eq!(unavailable.is_error, Some(true));
    assert_eq!(
        unavailable
            .structured_content
            .expect("resident anchor fault must be structured")["fault"]["code"],
        "anchor_lookup_unavailable"
    );
    let result = server.execute_tool_arguments(Some(tool_arguments(&request)));
    assert_eq!(structured_response(&result), direct);

    let mut changed: serde_json::Value =
        serde_json::from_slice(&fs::read(&resident.config_path).expect("config must read"))
            .expect("config must decode");
    changed["listen_address"] = json!("127.0.0.1:9");
    write_json(&resident.config_path, &changed);
    let pinned_result = server.execute_tool_arguments(Some(tool_arguments(&request)));
    assert_eq!(structured_response(&pinned_result), direct);

    let generation = resident.binding.generation_id.clone();
    resident.shutdown_with(&operator, generation);
    let unavailable = server.execute_tool_arguments(Some(tool_arguments(&request)));
    assert_eq!(unavailable.is_error, Some(true));
    assert_eq!(
        unavailable
            .structured_content
            .expect("transport fault must be structured")["fault"]["code"],
        "resident_service_transport_fault"
    );
}

#[test]
fn resident_backend_observes_refresh_without_rebinding_stale_requests() {
    let (environment, request) = fixture("cantor");
    let resident = LiveResident::start(&environment);
    let operator =
        ServiceClient::from_config(&resident.config_path).expect("operator client must load");
    let server = CantorMcpServer::from_service_config(&resident.config_path)
        .expect("resident-backed MCP must start");
    let old_binding = resident.binding.clone();

    let mut next_environment = environment.clone();
    next_environment.now_epoch_seconds += 1;
    let mut next_request = request.clone();
    next_request.expected_environment_digest =
        embedded_environment_digest(&next_environment).expect("next environment must digest");
    resident.publish(&next_environment, 2);
    let refresh = operator
        .send(
            ServiceOperation::Refresh {
                expected_generation_id: old_binding.generation_id,
                expected_activation_sequence: 1,
            },
            id("request:mcp_refresh"),
        )
        .expect("refresh exchange must complete");
    assert_eq!(refresh.disposition, ServiceDisposition::Success);
    let next_binding = refresh
        .active_binding
        .clone()
        .expect("refresh binding is required");

    let stale_expected = execute_protocol_request(&next_environment, request.clone());
    let stale = server.execute_tool_arguments(Some(tool_arguments(&request)));
    assert_eq!(structured_response(&stale), stale_expected);
    assert_eq!(stale.is_error, Some(true));

    let next_expected = execute_protocol_request(&next_environment, next_request.clone());
    let next = server.execute_tool_arguments(Some(tool_arguments(&next_request)));
    assert_eq!(structured_response(&next), next_expected);
    assert_eq!(next.is_error, Some(false));
    resident.shutdown_with(&operator, next_binding.generation_id);
}

#[tokio::test(flavor = "current_thread")]
async fn real_stdio_mcp_delegates_through_live_cantord() {
    let (environment, request) = fixture("cantor");
    let direct = execute_protocol_request(&environment, request.clone());
    let resident = LiveResident::start(&environment);
    let operator =
        ServiceClient::from_config(&resident.config_path).expect("operator client must load");
    let generation = resident.binding.generation_id.clone();

    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-mcp")).configure(|command| {
            command.arg("--service-config").arg(&resident.config_path);
        }),
    )
    .expect("service-backed MCP subprocess must start");
    let client = ().serve(transport).await.expect("MCP initialization must pass");
    let tools = client
        .list_all_tools()
        .await
        .expect("tools/list must succeed");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);
    let result = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(tool_arguments(&request)))
        .await
        .expect("service-backed tools/call must succeed");
    assert_eq!(structured_response(&result), direct);
    client.cancel().await.expect("MCP client must stop");
    resident.shutdown_with(&operator, generation);
}

#[test]
fn resident_startup_fails_closed_and_startup_modes_are_mutually_exclusive() {
    let (environment, _request) = fixture("cantor");
    let resident = LiveResident::start(&environment);
    let operator =
        ServiceClient::from_config(&resident.config_path).expect("operator client must load");
    fs::write(&resident.token_path, format!("{}\n", "f".repeat(64)))
        .expect("wrong token must write");
    let fault = CantorMcpServer::from_service_config(&resident.config_path)
        .expect_err("wrong service capability must fail MCP startup");
    assert_eq!(fault.code, "resident_service_unready");
    assert!(!fault.message.contains(SERVICE_TOKEN));

    for arguments in [
        Vec::<&str>::new(),
        vec!["--unknown", "value"],
        vec![
            "--environment",
            "environment.json",
            "--service-config",
            "service.json",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_cantor-mcp"))
            .args(arguments)
            .output()
            .expect("invalid startup subprocess must run");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("usage: cantor-mcp"));
    }
    let generation = resident.binding.generation_id.clone();
    resident.shutdown_with(&operator, generation);
}

struct LiveResident {
    root: PathBuf,
    config_path: PathBuf,
    activation_path: PathBuf,
    environment_path: PathBuf,
    token_path: PathBuf,
    binding: cantor_service::ActiveBinding,
    handle: thread::JoinHandle<Result<(), cantor_service::ServiceFault>>,
}

impl LiveResident {
    fn start(environment: &EmbeddedRuntimeEnvironment) -> Self {
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "cantor-mcp-resident-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("resident fixture root must create");
        let config_path = root.join("service.json");
        let activation_path = root.join("activation.json");
        let environment_path = root.join("environment.json");
        let token_path = root.join("token.txt");
        fs::write(&token_path, format!("{SERVICE_TOKEN}\n")).expect("service token must write");
        publish_environment(&environment_path, &activation_path, environment, 1);
        let mut config = ServiceConfig {
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
        let bound = BoundServer::bind(&config_path).expect("resident fixture must bind");
        let address = bound.local_addr().expect("fixture address is required");
        let binding = bound
            .runtime()
            .active_binding()
            .expect("fixture binding is required");
        config.listen_address = address.to_string();
        write_json(&config_path, &config);
        let handle = thread::spawn(move || bound.serve());
        Self {
            root,
            config_path,
            activation_path,
            environment_path,
            token_path,
            binding,
            handle,
        }
    }

    fn publish(&self, environment: &EmbeddedRuntimeEnvironment, sequence: u64) {
        publish_environment(
            &self.environment_path,
            &self.activation_path,
            environment,
            sequence,
        );
    }

    fn shutdown_with(
        self,
        operator: &ServiceClient,
        expected_generation_id: cantor_core::ContentDigest,
    ) {
        let response = operator
            .send(
                ServiceOperation::Shutdown {
                    expected_generation_id,
                },
                id("request:mcp_resident_shutdown"),
            )
            .expect("resident shutdown must exchange");
        assert!(matches!(
            response.result,
            Some(ServiceResult::Shutdown { .. })
        ));
        self.handle
            .join()
            .expect("resident thread must join")
            .expect("resident service must stop cleanly");
        fs::remove_dir_all(&self.root).expect("resident fixture must clean");
    }
}

fn publish_environment(
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
        environment_file_sha256: cantor_core::sha256_bytes(&bytes).value,
    };
    write_json(activation_path, &activation);
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("fixture JSON must encode");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("fixture JSON must write");
}
