mod support;
use cantor_sop_inspect_mcp::{
    InspectionMcpServer, MAX_INPUT_BYTES, MAX_MESSAGES, MAX_RESERVED_OUTPUT_BYTES, TOOL_NAME,
    run_io,
};
use rmcp::{ServerHandler, ServiceExt, model::CallToolRequestParams};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn official_sdk_client_initializes_lists_replays_and_recovers() {
    timeout(Duration::from_secs(10), async {
        let (client_io, server_io) = tokio::io::duplex(16_384);
        let (read, write) = tokio::io::split(server_io);
        let server = tokio::spawn(run_io(read, write));
        let mut client = ().serve(client_io).await.unwrap();
        let tools = client.list_tools(Default::default()).await.unwrap();
        assert_eq!(tools.tools.len(), 1);
        assert_eq!(tools.tools[0].name, TOOL_NAME);
        let error = client
            .call_tool(CallToolRequestParams::new("unknown"))
            .await
            .unwrap_err();
        assert!(matches!(error,rmcp::service::ServiceError::McpError(data)
            if data.code == rmcp::model::ErrorCode::METHOD_NOT_FOUND));
        for fixture in support::fixtures() {
            let result = client
                .call_tool(
                    CallToolRequestParams::new(TOOL_NAME)
                        .with_arguments(support::arguments(&fixture.request)),
                )
                .await
                .unwrap();
            support::check_fixture(
                &fixture,
                &support::reply(result.structured_content.unwrap()),
            );
        }
        client.close().await.unwrap();
        drop(client);
        let report = server.await.unwrap().unwrap();
        assert!(report.input_bytes <= MAX_INPUT_BYTES);
        assert!(report.reserved_output_bytes <= MAX_RESERVED_OUTPUT_BYTES);
        assert!(report.decoded_messages <= MAX_MESSAGES);
    })
    .await
    .unwrap();
}

#[test]
fn metadata_is_one_readonly_closed_world_tools_capability() {
    let server = InspectionMcpServer::default();
    let info = server.get_info();
    let value = serde_json::to_value(info.capabilities).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 1);
    assert!(value.get("tools").is_some());
    let tool = server.get_tool(TOOL_NAME).unwrap();
    let annotation = tool.annotations.unwrap();
    assert_eq!(annotation.read_only_hint, Some(true));
    assert_eq!(annotation.destructive_hint, Some(false));
    assert_eq!(annotation.idempotent_hint, Some(true));
    assert_eq!(annotation.open_world_hint, Some(false));
    assert!(server.get_tool("run_command").is_none());
}
