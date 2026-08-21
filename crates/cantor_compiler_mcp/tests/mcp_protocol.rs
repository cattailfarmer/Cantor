use cantor_compiler_mcp::{CompilerMcpServer, MAX_ARGUMENT_BYTES, SERVER_INSTRUCTIONS, TOOL_NAME};
use cantor_core::{
    NativeLifecycleValidationFaultKind, NativeLifecycleValidationOutcome,
    NativeLifecycleValidationResponse,
};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

fn governed_valid_lifecycle_request() -> cantor_core::NativeLifecycleValidationRequest {
    serde_json::from_slice(include_bytes!(
        "../../../fixtures/semantic_compiler/native_lifecycle_valid_request.json"
    ))
    .expect("governed valid lifecycle request fixture")
}

fn structured(result: &rmcp::model::CallToolResult) -> NativeLifecycleValidationResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("structured response"),
    )
    .expect("typed native lifecycle response")
}

#[test]
fn metadata_declares_one_bounded_read_only_closed_world_tool() {
    let tool = CompilerMcpServer::tool_definition();
    assert_eq!(tool.name, TOOL_NAME);
    assert!(tool.output_schema.is_some());
    assert_eq!(
        tool.input_schema.get("additionalProperties"),
        Some(&json!(false))
    );
    assert_eq!(tool.input_schema.get("required"), Some(&json!(["request"])));
    let annotations = tool.annotations.expect("tool annotations");
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert!(SERVER_INSTRUCTIONS.contains("does not establish physical truth"));
    assert!(SERVER_INSTRUCTIONS.contains("stores no lifecycle state"));
    assert!(
        serde_json::to_vec(&tool.input_schema)
            .expect("input schema JSON")
            .len()
            < 4096
    );
}

#[test]
fn malformed_extra_and_oversized_arguments_fail_before_core_dispatch() {
    let server = CompilerMcpServer;
    for value in [json!({}), json!({ "request": {}, "repair": true })] {
        let result = server
            .execute_tool_arguments(Some(value.as_object().expect("argument object").clone()));
        assert_eq!(result.is_error, Some(true));
        let response = structured(&result);
        assert_eq!(
            response.outcome,
            NativeLifecycleValidationOutcome::InputRefused
        );
        assert_eq!(
            response.faults[0].kind,
            NativeLifecycleValidationFaultKind::Wire
        );
        assert!(response.stage_account.is_empty());
    }

    let result = server.execute_tool_arguments(Some(
        json!({ "padding": "x".repeat(MAX_ARGUMENT_BYTES) })
            .as_object()
            .expect("argument object")
            .clone(),
    ));
    let response = structured(&result);
    assert_eq!(
        response.faults[0].kind,
        NativeLifecycleValidationFaultKind::InvalidBound
    );
}

#[tokio::test(flavor = "current_thread")]
async fn official_client_lists_one_tool_and_receives_exact_valid_response() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-compiler-mcp")).configure(|_| {}),
    )
    .expect("MCP subprocess starts");
    let client = ().serve(transport).await.expect("MCP initializes");
    let tools = client.list_all_tools().await.expect("tools/list succeeds");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);

    let request = governed_valid_lifecycle_request();
    let direct = cantor_core::validate_native_lifecycle_request(&request);
    let result = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(
                json!({ "request": request })
                    .as_object()
                    .expect("arguments")
                    .clone(),
            ),
        )
        .await
        .expect("tools/call succeeds");
    assert_eq!(result.is_error, Some(false));
    let response: NativeLifecycleValidationResponse =
        serde_json::from_value(result.structured_content.expect("structured response"))
            .expect("typed response");
    assert_eq!(response, direct);

    client
        .call_tool(CallToolRequestParams::new("unknown_compiler_operation"))
        .await
        .expect_err("unknown tool name must remain a protocol method fault");
    client.cancel().await.expect("client closes");
}

#[tokio::test(flavor = "current_thread")]
async fn slice11_bridge_sends_each_full_governed_request_and_preserves_both_outcomes() {
    use cantor_lifecycle_tool_loop::{
        GovernedLifecycleFixture, LifecycleFixtureCase, McpArm, StatelessSession,
    };

    let session = StatelessSession::open(
        std::path::Path::new(env!("CARGO_BIN_EXE_cantor-compiler-mcp")),
        std::time::Duration::from_secs(5),
    )
    .await
    .expect("Slice11 stateless bridge opens");
    for case in [
        LifecycleFixtureCase::Valid,
        LifecycleFixtureCase::LifecycleRefused,
    ] {
        let fixture = GovernedLifecycleFixture::load(case).expect("governed fixture");
        let observation = session.validate(&fixture).await.expect("bridge validation");
        assert_eq!(observation.arm, McpArm::Stateless);
        assert!(observation.argument_bytes > fixture.request_bytes.len());
        assert!(observation.exact_direct_response);
        assert_eq!(observation.lifecycle_response, fixture.direct_response);
    }
    session
        .close()
        .await
        .expect("Slice11 stateless bridge closes");
}

#[test]
fn direct_adapter_preserves_exact_valid_core_response() {
    let server = CompilerMcpServer;
    let request = governed_valid_lifecycle_request();
    let direct = cantor_core::validate_native_lifecycle_request(&request);
    let arguments = Some(
        json!({ "request": request })
            .as_object()
            .expect("arguments")
            .clone(),
    );
    let first = server.execute_tool_arguments(arguments.clone());
    let second = server.execute_tool_arguments(arguments);
    assert_eq!(first.is_error, Some(false));
    assert_eq!(second.is_error, Some(false));
    assert_eq!(structured(&first), direct);
    assert_eq!(structured(&second), direct);
}

#[test]
fn structured_refusal_is_deterministic_and_summary_is_bounded() {
    let server = CompilerMcpServer;
    let arguments = Some(json!({}).as_object().expect("arguments").clone());
    let first = server.execute_tool_arguments(arguments.clone());
    let second = server.execute_tool_arguments(arguments);
    assert_eq!(first, second);
    assert!(first.content[0].as_text().expect("summary text").text.len() < 180);
    let value: Value = first.structured_content.expect("structured response");
    assert_eq!(value["outcome"], "input_refused");
}
