use std::collections::{BTreeMap, BTreeSet};

use cantor_coordination_mcp::{
    CoordinationMcpServer, MAX_ARGUMENT_BYTES, SERVER_INSTRUCTIONS, TOOL_NAME,
};
use cantor_core::*;
use cantor_procedure_tool::{
    CoordinationToolContext, CoordinationToolRequest, CoordinationToolResponse,
    CoordinationToolStatus, execute_coordination_tool_request,
};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn candidate() -> ProcedureCandidate {
    let mut candidate: ProcedureCandidate = serde_json::from_str(include_str!(
        "../../cantor_core/tests/fixtures/cppe_two_process_candidate.json"
    ))
    .expect("checked two-process candidate fixture");
    candidate.candidate_id = sid("tool-candidate:coordination-mcp");
    candidate.author_ref = sid("model-output:coordination-mcp-author");
    candidate.provenance_refs = BTreeSet::from([sid("evidence:coordination-mcp")]);
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).expect("candidate source digest");
    candidate
}

fn template() -> AuthorshipLaneTemplate {
    AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:coordination-mcp")]),
        validator_ref: sid("validator:coordination-mcp"),
        policy_ref: sid("policy:coordination-mcp"),
        aliases: BTreeSet::from(["coordination-mcp".to_owned()]),
        permitted_invocation_context: "effectless-coordination-mcp".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("invocation:coordination-mcp"),
        caller_ref: sid("caller:coordination-mcp"),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:coordination-mcp"),
        initial_logical_time: 20,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention"),
        session_generation_ref: sid("session-generation:coordination-mcp"),
        session_ref: sid("session:coordination-mcp"),
        session_purpose: "prove the real local MCP transport".to_owned(),
        frame_ref: sid("frame:coordination-mcp"),
        frame_conditions: BTreeSet::from(["effectless".to_owned()]),
        frame_constraints: BTreeSet::from(["provider-neutral".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    }
}

fn request() -> CoordinationToolRequest {
    let lane = run_authorship_lane(&candidate(), &template(), &BTreeMap::new())
        .expect("coordination MCP lane");
    CoordinationToolRequest::Begin {
        context: Box::new(CoordinationToolContext::from(&lane)),
    }
}

fn arguments(request: &CoordinationToolRequest) -> serde_json::Map<String, Value> {
    json!({ "request": request })
        .as_object()
        .expect("tool arguments are an object")
        .clone()
}

fn structured(result: &rmcp::model::CallToolResult) -> CoordinationToolResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("structured coordination result"),
    )
    .expect("typed coordination response")
}

#[test]
fn metadata_declares_one_bounded_read_only_closed_world_tool() {
    let tool = CoordinationMcpServer::tool_definition();
    assert_eq!(tool.name, TOOL_NAME);
    assert!(tool.output_schema.is_some());
    let annotations = tool.annotations.as_ref().expect("annotations");
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert_eq!(
        tool.input_schema.get("additionalProperties"),
        Some(&json!(false))
    );
    let schema = serde_json::to_string(&tool.input_schema).expect("schema encodes");
    for required in ["begin", "advance", "maximum_steps", "checkpoint"] {
        assert!(schema.contains(required), "missing schema term {required}");
    }
    assert!(SERVER_INSTRUCTIONS.contains("between inference passes"));
    assert!(SERVER_INSTRUCTIONS.contains("stores no context or checkpoint"));
    assert!(
        serde_json::to_vec(&tool)
            .expect("tool metadata encodes")
            .len()
            < 8 * 1024 * 1024
    );
}

#[test]
fn direct_mcp_result_is_exactly_dispatch_equivalent_and_repeatable() {
    let request = request();
    let direct = execute_coordination_tool_request(request.clone());
    let server = CoordinationMcpServer;
    let first = server.execute_tool_arguments(Some(arguments(&request)));
    let second = server.execute_tool_arguments(Some(arguments(&request)));
    assert_eq!(first.is_error, Some(false));
    assert_eq!(structured(&first), direct);
    assert_eq!(structured(&second), direct);
    assert!(first.content[0].as_text().expect("summary text").text.len() < 180);
}

#[test]
fn malformed_extra_and_oversized_arguments_fail_before_dispatch() {
    let request = request();
    let server = CoordinationMcpServer;
    let malformed = server.execute_tool_arguments(Some(
        json!({ "request": request, "invented_authority": true })
            .as_object()
            .expect("arguments object")
            .clone(),
    ));
    assert_eq!(malformed.is_error, Some(true));
    let response = structured(&malformed);
    assert_eq!(response.status, CoordinationToolStatus::InvalidRequest);
    assert_eq!(
        response.fault.expect("argument fault").code,
        "invalid_arguments"
    );

    let oversized = server.execute_tool_arguments(Some(
        json!({ "padding": "x".repeat(MAX_ARGUMENT_BYTES) })
            .as_object()
            .expect("arguments object")
            .clone(),
    ));
    assert_eq!(oversized.is_error, Some(true));
    assert_eq!(
        structured(&oversized).fault.expect("size fault").code,
        "argument_limit_exceeded"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn official_client_lists_one_tool_and_receives_exact_response() {
    let request = request();
    let direct = execute_coordination_tool_request(request.clone());
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-coordination-mcp"))
            .configure(|_| {}),
    )
    .expect("coordination MCP subprocess starts");
    let client = ().serve(transport).await.expect("MCP initializes");
    let tools = client.list_all_tools().await.expect("tools/list succeeds");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);

    let result = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments(&request)))
        .await
        .expect("tools/call succeeds");
    assert_eq!(result.is_error, Some(false));
    let response: CoordinationToolResponse = serde_json::from_value(
        result
            .structured_content
            .expect("official response has structured content"),
    )
    .expect("official response is typed");
    assert_eq!(response, direct);
    client.cancel().await.expect("client closes");
}
