use cantor_compiler_custody_mcp::{
    CompilerCustodyMcpServer, CustodyResponse, CustodyStatus, MAX_ARGUMENT_BYTES,
    SERVER_INSTRUCTIONS, TOOL_NAME,
};
use cantor_core::{NativeLifecycleValidationOutcome, validate_native_lifecycle_request};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

#[path = "../../cantor_core/tests/semantic_compiler_native_artifact_backend.rs"]
mod native_lifecycle_fixture;

fn arguments(value: Value) -> Option<serde_json::Map<String, Value>> {
    Some(value.as_object().expect("arguments object").clone())
}

fn structured(result: &rmcp::model::CallToolResult) -> CustodyResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("structured response"),
    )
    .expect("typed custody response")
}

#[test]
fn metadata_declares_one_bounded_volatile_closed_world_tool() {
    let tool = CompilerCustodyMcpServer::tool_definition();
    assert_eq!(tool.name, TOOL_NAME);
    assert!(tool.output_schema.is_some());
    assert_eq!(tool.input_schema["additionalProperties"], false);
    assert_eq!(tool.input_schema["required"], json!(["command"]));
    let annotations = tool.annotations.as_ref().expect("annotations");
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert!(SERVER_INSTRUCTIONS.contains("restart loses all entries"));
    let tool_bytes = serde_json::to_vec(&tool).expect("tool bytes").len();
    println!("custody_tool_bytes={tool_bytes}");
    assert!(tool_bytes < 8_192);
}

#[tokio::test(flavor = "current_thread")]
async fn register_inspect_and_compact_validate_preserve_exact_core_result() {
    let server = CompilerCustodyMcpServer::new().expect("server");
    let request = native_lifecycle_fixture::exported_artifact_validation_request();
    let direct = validate_native_lifecycle_request(&request);
    let register_arguments = json!({
        "command": {"operation": "register", "request": request}
    });
    let registered = server
        .execute_tool_arguments(arguments(register_arguments.clone()))
        .await;
    assert_eq!(registered.is_error, Some(false));
    let registered = structured(&registered);
    assert_eq!(registered.status, CustodyStatus::Registered);
    assert_eq!(
        registered.registry.as_ref().expect("summary").entry_count,
        1
    );
    let handle = registered.handle.expect("handle");

    let inspected = server
        .execute_tool_arguments(arguments(json!({"command": {"operation": "inspect"}})))
        .await;
    let inspected_value = inspected.structured_content.clone().expect("inspect value");
    assert!(inspected_value["handle"].is_null());
    assert!(inspected_value["lifecycle_response"].is_null());
    let inspect_bytes = serde_json::to_vec(&inspected_value)
        .expect("inspect bytes")
        .len();
    assert!(inspect_bytes < 2_048);
    assert_eq!(structured(&inspected).status, CustodyStatus::Inspected);

    let validate_arguments = json!({
        "command": {"operation": "validate", "handle": handle}
    });
    let validate_bytes = serde_json::to_vec(&validate_arguments)
        .expect("validate bytes")
        .len();
    let register_bytes = serde_json::to_vec(&register_arguments)
        .expect("register bytes")
        .len();
    println!(
        "custody_register_bytes={register_bytes} custody_validate_bytes={validate_bytes} custody_inspect_bytes={inspect_bytes}"
    );
    assert!(validate_bytes * 4 < register_bytes);
    let validated = server
        .execute_tool_arguments(arguments(validate_arguments))
        .await;
    assert_eq!(validated.is_error, Some(false));
    assert_eq!(structured(&validated).lifecycle_response, Some(direct));
}

#[tokio::test(flavor = "current_thread")]
async fn refused_request_is_retained_without_outer_success_laundering() {
    let server = CompilerCustodyMcpServer::new().expect("server");
    let mut request = native_lifecycle_fixture::exported_artifact_validation_request();
    request.protocol.push_str(".unsupported");
    let registered = server
        .execute_tool_arguments(arguments(json!({
            "command": {"operation": "register", "request": request}
        })))
        .await;
    assert_eq!(registered.is_error, Some(false));
    let handle = structured(&registered).handle.expect("handle");
    let validated = server
        .execute_tool_arguments(arguments(json!({
            "command": {"operation": "validate", "handle": handle}
        })))
        .await;
    assert_eq!(validated.is_error, Some(true));
    let response = structured(&validated);
    assert_eq!(response.status, CustodyStatus::Validated);
    assert_eq!(
        response.lifecycle_response.expect("lifecycle").outcome,
        NativeLifecycleValidationOutcome::LifecycleRefused
    );
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_missing_malformed_oversized_and_restart_refuse_without_mutation() {
    let server = CompilerCustodyMcpServer::new().expect("server");
    let request = native_lifecycle_fixture::exported_artifact_validation_request();
    let command = json!({"command": {"operation": "register", "request": request}});
    let registered = server
        .execute_tool_arguments(arguments(command.clone()))
        .await;
    let handle = structured(&registered).handle.expect("handle");
    let after_register = server.snapshot().await;
    for (label, invalid) in [
        ("duplicate", command),
        ("missing", json!({})),
        (
            "extra",
            json!({"command": {"operation": "inspect", "extra": true}}),
        ),
    ] {
        let result = server.execute_tool_arguments(arguments(invalid)).await;
        assert_eq!(result.is_error, Some(true), "{label}");
        assert_eq!(server.snapshot().await, after_register);
    }
    let oversized = server
        .execute_tool_arguments(arguments(
            json!({"padding": "x".repeat(MAX_ARGUMENT_BYTES)}),
        ))
        .await;
    assert_eq!(oversized.is_error, Some(true));
    assert_eq!(server.snapshot().await, after_register);

    let mut missing = handle.clone();
    missing.request_digest.value.replace_range(0..1, "0");
    if missing.request_digest == handle.request_digest {
        missing.request_digest.value.replace_range(0..1, "1");
    }
    let result = server
        .execute_tool_arguments(arguments(json!({
            "command": {"operation": "validate", "handle": missing}
        })))
        .await;
    assert_eq!(structured(&result).status, CustodyStatus::Refused);
    assert_eq!(server.snapshot().await, after_register);

    let restarted = CompilerCustodyMcpServer::new().expect("restart");
    let result = restarted
        .execute_tool_arguments(arguments(json!({
            "command": {"operation": "validate", "handle": handle}
        })))
        .await;
    assert_eq!(structured(&result).status, CustodyStatus::Refused);
    assert_eq!(restarted.snapshot().await.entry_count, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_equal_registration_admits_exactly_one_successor() {
    let server = CompilerCustodyMcpServer::new().expect("server");
    let request = native_lifecycle_fixture::exported_artifact_validation_request();
    let payload = arguments(json!({"command": {"operation": "register", "request": request}}));
    let left = server.clone();
    let right = server.clone();
    let (first, second) = tokio::join!(
        left.execute_tool_arguments(payload.clone()),
        right.execute_tool_arguments(payload)
    );
    let statuses = [structured(&first).status, structured(&second).status];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == CustodyStatus::Registered)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == CustodyStatus::Refused)
            .count(),
        1
    );
    assert_eq!(server.snapshot().await.entry_count, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn official_client_registers_inspects_validates_and_unknown_method_refuses() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-compiler-custody-mcp"))
            .configure(|_| {}),
    )
    .expect("MCP subprocess starts");
    let client = ().serve(transport).await.expect("MCP initializes");
    let tools = client.list_all_tools().await.expect("tools/list");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);

    let request = native_lifecycle_fixture::exported_artifact_validation_request();
    let direct = validate_native_lifecycle_request(&request);
    let registered = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(
                arguments(json!({"command": {"operation": "register", "request": request}}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("register");
    let handle = structured(&registered).handle.expect("handle");
    let inspected = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(
            arguments(json!({"command": {"operation": "inspect"}})).expect("arguments"),
        ))
        .await
        .expect("inspect");
    assert_eq!(structured(&inspected).status, CustodyStatus::Inspected);
    let validated = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(
                arguments(json!({"command": {"operation": "validate", "handle": handle.clone()}}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("validate");
    assert_eq!(structured(&validated).lifecycle_response, Some(direct));
    client
        .call_tool(CallToolRequestParams::new("unknown_custody_operation"))
        .await
        .expect_err("unknown tool remains a method fault");
    client.cancel().await.expect("client closes");

    let restarted_transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-compiler-custody-mcp"))
            .configure(|_| {}),
    )
    .expect("restarted MCP subprocess starts");
    let restarted = ().serve(restarted_transport).await.expect("restart initializes");
    let lost = restarted
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(
                arguments(json!({"command": {"operation": "validate", "handle": handle}}))
                    .expect("arguments"),
            ),
        )
        .await
        .expect("restart handle refusal");
    assert_eq!(structured(&lost).status, CustodyStatus::Refused);
    restarted.cancel().await.expect("restarted client closes");
}
