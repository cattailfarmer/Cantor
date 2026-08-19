use std::collections::{BTreeMap, BTreeSet};

use cantor_core::{
    ATTENTION_BYTE_PROXY_PROFILE, ATTENTION_DELTA_PROFILE, AttentionCapacity, AttentionFrameDelta,
    AttentionParticipant, ContentDigest, EpistemicStatus, FacultyKind, FrameDeltaOperation,
    FramedProposition, SemanticId, SharedAttentionFrame, SharedAttentionFrameSeed,
    SharedAttentionToolRequest, SharedAttentionToolResponse, SharedAttentionToolStatus,
    execute_shared_attention_tool_request, finalize_attention_delta, new_shared_attention_frame,
};
use cantor_shared_attention_mcp::{
    MAX_ARGUMENT_BYTES, SERVER_INSTRUCTIONS, SharedAttentionMcpServer, TOOL_NAME,
};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture semantic identity")
}

fn empty_digest() -> ContentDigest {
    ContentDigest {
        algorithm: "sha256".to_owned(),
        value: String::new(),
    }
}

fn frame(headroom: u64) -> SharedAttentionFrame {
    let guard = AttentionParticipant {
        participant_id: sid("participant:guard"),
        faculties: BTreeSet::from([FacultyKind::Honesty, FacultyKind::Security]),
        required: true,
    };
    let projection = AttentionParticipant {
        participant_id: sid("participant:projection"),
        faculties: BTreeSet::from([FacultyKind::Planner, FacultyKind::Weaver]),
        required: true,
    };
    let server = AttentionParticipant {
        participant_id: sid("participant:server"),
        faculties: BTreeSet::from([
            FacultyKind::Observer,
            FacultyKind::Scribe,
            FacultyKind::Refiner,
        ]),
        required: true,
    };
    let proposition = FramedProposition {
        proposition_id: sid("proposition:mcp-base"),
        text: "Cantor coordinates exact semantic state between passes.".to_owned(),
        epistemic_status: EpistemicStatus::Observed,
        source_refs: BTreeSet::from([sid("source:mcp-fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: None,
    };
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:mcp-fixture"),
        purpose: "prove the stateless MCP transport seam".to_owned(),
        policy_ref: sid("policy:mcp-fixture"),
        participants: BTreeMap::from([
            (guard.participant_id.clone(), guard),
            (projection.participant_id.clone(), projection),
            (server.participant_id.clone(), server),
        ]),
        propositions: BTreeMap::from([(proposition.proposition_id.clone(), proposition)]),
        constraints: BTreeMap::from([(
            sid("constraint:no-hidden-state"),
            "the adapter does not share model hidden state".to_owned(),
        )]),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::from([sid("proposition:mcp-base")]),
        capacity: AttentionCapacity {
            accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
            context_budget_bytes: 2_000_000,
            pinned_anchor_bytes: 0,
            current_focus_bytes: 100,
            retrieved_association_bytes: 0,
            recent_stream_bytes: 0,
            reserved_headroom_bytes: headroom,
        },
    })
    .expect("fixture frame")
}

fn delta(base: &SharedAttentionFrame) -> AttentionFrameDelta {
    finalize_attention_delta(AttentionFrameDelta {
        profile: ATTENTION_DELTA_PROFILE.to_owned(),
        delta_id: sid("delta:mcp-fixture"),
        author_ref: sid("participant:guard"),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        logical_time: 1,
        operations: vec![FrameDeltaOperation::AttachEvidence {
            evidence_ref: sid("evidence:mcp-fixture"),
        }],
        causal_predecessor_refs: BTreeSet::new(),
        delta_digest: empty_digest(),
    })
    .expect("fixture delta")
}

fn arguments(request: &SharedAttentionToolRequest) -> serde_json::Map<String, Value> {
    json!({ "request": request })
        .as_object()
        .expect("tool arguments are an object")
        .clone()
}

fn structured(result: &rmcp::model::CallToolResult) -> SharedAttentionToolResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("tool result has structured content"),
    )
    .expect("structured response has the shared tool form")
}

#[test]
fn metadata_is_closed_bounded_and_lists_every_operation() {
    let tool = SharedAttentionMcpServer::tool_definition();
    assert_eq!(tool.name, TOOL_NAME);
    assert!(tool.output_schema.is_some());
    let annotations = tool.annotations.as_ref().expect("tool annotations");
    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert_eq!(
        tool.input_schema.get("additionalProperties"),
        Some(&json!(false))
    );
    let schema = serde_json::to_string(&tool.input_schema).expect("input schema encodes");
    for operation in [
        "validate_frame",
        "reconcile",
        "compact",
        "prepare",
        "settle",
        "fork_dream",
        "validate_dream",
        "record_dream_evidence",
        "review_dream",
        "discard_dream",
        "project_dream_promotion",
    ] {
        assert!(schema.contains(operation), "missing schema tag {operation}");
    }
    assert_eq!(
        SharedAttentionMcpServer::tool_definition().input_schema,
        tool.input_schema
    );
    assert!(
        serde_json::to_vec(&tool)
            .expect("tool metadata encodes")
            .len()
            < 1_048_576
    );
    assert!(SERVER_INSTRUCTIONS.contains("stores no frame"));
    assert!(SERVER_INSTRUCTIONS.contains("not externally proven true"));
}

#[test]
fn direct_mcp_success_is_exactly_core_equivalent_and_repeatable() {
    let request = SharedAttentionToolRequest::ValidateFrame {
        frame: frame(1_000_000),
    };
    let direct = execute_shared_attention_tool_request(request.clone());
    let server = SharedAttentionMcpServer;
    let first = server.execute_tool_arguments(Some(arguments(&request)));
    let second = server.execute_tool_arguments(Some(arguments(&request)));

    assert_eq!(first.is_error, Some(false));
    assert_eq!(structured(&first), direct);
    assert_eq!(structured(&second), direct);
    assert!(first.content[0].as_text().expect("summary text").text.len() < 180);
}

#[test]
fn buffered_and_refused_dispositions_preserve_distinct_mcp_status() {
    let constrained = frame(1);
    let buffered_request = SharedAttentionToolRequest::Reconcile {
        base: constrained.clone(),
        deltas: vec![delta(&constrained)],
    };
    let server = SharedAttentionMcpServer;
    let buffered = server.execute_tool_arguments(Some(arguments(&buffered_request)));
    assert_eq!(buffered.is_error, Some(false));
    assert_eq!(
        structured(&buffered).status,
        SharedAttentionToolStatus::Buffered
    );
    assert_eq!(
        structured(&buffered),
        execute_shared_attention_tool_request(buffered_request)
    );

    let base = frame(1_000_000);
    let mut stale = delta(&base);
    stale.base_generation += 1;
    stale = finalize_attention_delta(stale).expect("stale delta is internally signed");
    let refused_request = SharedAttentionToolRequest::Reconcile {
        base,
        deltas: vec![stale],
    };
    let refused = server.execute_tool_arguments(Some(arguments(&refused_request)));
    assert_eq!(refused.is_error, Some(true));
    let response = structured(&refused);
    assert_eq!(response.status, SharedAttentionToolStatus::Refused);
    assert_eq!(response.fault.expect("refusal fault").code, "stale_base");
}

#[test]
fn malformed_extra_and_oversized_arguments_fail_before_dispatch() {
    let request = SharedAttentionToolRequest::ValidateFrame {
        frame: frame(1_000_000),
    };
    let server = SharedAttentionMcpServer;
    let malformed = server.execute_tool_arguments(Some(
        json!({ "request": request, "invented_authority": true })
            .as_object()
            .expect("arguments object")
            .clone(),
    ));
    assert_eq!(malformed.is_error, Some(true));
    let response = structured(&malformed);
    assert_eq!(response.status, SharedAttentionToolStatus::InvalidRequest);
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
    let request = SharedAttentionToolRequest::ValidateFrame {
        frame: frame(1_000_000),
    };
    let direct = execute_shared_attention_tool_request(request.clone());
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-shared-attention-mcp"))
            .configure(|_| {}),
    )
    .expect("MCP subprocess starts");
    let client = ().serve(transport).await.expect("MCP initializes");
    let tools = client.list_all_tools().await.expect("tools/list succeeds");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);

    let result = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments(&request)))
        .await
        .expect("tools/call succeeds");
    assert_eq!(result.is_error, Some(false));
    let response: SharedAttentionToolResponse = serde_json::from_value(
        result
            .structured_content
            .expect("official response has structured content"),
    )
    .expect("official response is typed");
    assert_eq!(response, direct);
    client.cancel().await.expect("client closes");
}
