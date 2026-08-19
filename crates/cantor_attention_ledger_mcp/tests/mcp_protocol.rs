use std::collections::{BTreeMap, BTreeSet};

use cantor_attention_ledger_mcp::{
    AttentionLedgerMcpResponse, AttentionLedgerMcpServer, LedgerMcpStatus, SERVER_INSTRUCTIONS,
    TOOL_NAME,
};
use cantor_core::{
    ATTENTION_BYTE_PROXY_PROFILE, ATTENTION_COMPACTION_PROFILE, AttentionCapacity,
    AttentionCompaction, AttentionLedgerCommand, AttentionParticipant, AttentionSessionOperation,
    ContentDigest, EpistemicStatus, FacultyKind, FramedProposition, SemanticId,
    SharedAttentionFrame, SharedAttentionFrameSeed, finalize_attention_compaction,
    new_attention_ledger, new_shared_attention_frame,
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

fn frame() -> SharedAttentionFrame {
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
        proposition_id: sid("proposition:mcp-ledger-base"),
        text: "The local ledger returns exact continuation handles.".to_owned(),
        epistemic_status: EpistemicStatus::Observed,
        source_refs: BTreeSet::from([sid("source:mcp-ledger-fixture")]),
        evidence_refs: BTreeSet::new(),
        dream_ref: None,
    };
    new_shared_attention_frame(SharedAttentionFrameSeed {
        frame_id: sid("frame:mcp-ledger-fixture"),
        purpose: "prove local MCP reentry".to_owned(),
        policy_ref: sid("policy:mcp-ledger-fixture"),
        participants: BTreeMap::from([
            (guard.participant_id.clone(), guard),
            (projection.participant_id.clone(), projection),
            (server.participant_id.clone(), server),
        ]),
        propositions: BTreeMap::from([(proposition.proposition_id.clone(), proposition)]),
        constraints: BTreeMap::from([(
            sid("constraint:volatile"),
            "process state is not durable".to_owned(),
        )]),
        pinned_sop_anchor_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
        current_focus_refs: BTreeSet::from([sid("proposition:mcp-ledger-base")]),
        capacity: AttentionCapacity {
            accounting_profile: ATTENTION_BYTE_PROXY_PROFILE.to_owned(),
            context_budget_bytes: 2_000_000,
            pinned_anchor_bytes: 0,
            current_focus_bytes: 100,
            retrieved_association_bytes: 200,
            recent_stream_bytes: 300,
            reserved_headroom_bytes: 1,
        },
    })
    .expect("fixture frame")
}

fn compaction(base: &SharedAttentionFrame) -> AttentionCompaction {
    finalize_attention_compaction(AttentionCompaction {
        profile: ATTENTION_COMPACTION_PROFILE.to_owned(),
        compaction_id: sid("compaction:mcp-ledger"),
        actor_ref: sid("participant:server"),
        policy_ref: base.policy_ref.clone(),
        base_generation: base.generation,
        base_frame_digest: base.frame_digest.clone(),
        retained_focus_refs: BTreeSet::new(),
        current_focus_bytes_after: 0,
        retrieved_association_bytes_after: 0,
        recent_stream_bytes_after: 0,
        rationale: "release complete focus for reentry".to_owned(),
        evidence_refs: BTreeSet::from([sid("evidence:mcp-ledger")]),
        compaction_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    })
    .expect("fixture compaction")
}

fn arguments(request: AttentionLedgerCommand) -> serde_json::Map<String, Value> {
    json!({ "request": request })
        .as_object()
        .expect("tool arguments are an object")
        .clone()
}

fn structured(result: &rmcp::model::CallToolResult) -> AttentionLedgerMcpResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("structured ledger result"),
    )
    .expect("typed ledger MCP response")
}

#[test]
fn metadata_declares_one_volatile_mutating_closed_world_tool() {
    let tool = AttentionLedgerMcpServer::tool_definition();
    assert_eq!(tool.name, TOOL_NAME);
    assert!(tool.output_schema.is_some());
    let annotations = tool.annotations.as_ref().expect("annotations");
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(false));
    assert_eq!(
        tool.input_schema.get("additionalProperties"),
        Some(&json!(false))
    );
    let schema = serde_json::to_string(&tool.input_schema).expect("schema encodes");
    for command in ["open", "apply", "inspect", "read_frame", "read_event"] {
        assert!(schema.contains(command), "missing command {command}");
    }
    assert!(SERVER_INSTRUCTIONS.contains("restart loses"));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_open_apply_inspect_and_read_share_one_exact_ledger() {
    let ledger_id = sid("ledger:mcp-direct");
    let server = AttentionLedgerMcpServer::new(ledger_id.clone()).expect("server");
    let empty = new_attention_ledger(ledger_id).expect("empty mirror");
    let initial = frame();
    let opened = server
        .execute_tool_arguments(Some(arguments(AttentionLedgerCommand::Open {
            expected_ledger_digest: empty.ledger_digest,
            session_id: sid("session:mcp-direct"),
            frame: Box::new(initial.clone()),
        })))
        .await;
    assert_eq!(opened.is_error, Some(false));
    let opened = structured(&opened);
    let handle = opened
        .result
        .expect("open result")
        .continuation
        .expect("open continuation");

    let applied = server
        .execute_tool_arguments(Some(arguments(AttentionLedgerCommand::Apply {
            expected_ledger_digest: handle.ledger_digest.clone(),
            session_id: handle.session_id.clone(),
            expected_sequence: handle.session_sequence,
            expected_head_frame_digest: handle.head_frame_digest.clone(),
            session_operation: AttentionSessionOperation::Compact {
                compaction: Box::new(compaction(&initial)),
            },
        })))
        .await;
    assert_eq!(applied.is_error, Some(false));
    let next = structured(&applied)
        .result
        .expect("apply result")
        .continuation
        .expect("apply continuation");
    assert_eq!(next.session_sequence, 2);
    assert_ne!(next.head_frame_digest, initial.frame_digest);

    let inspected = server
        .execute_tool_arguments(Some(arguments(AttentionLedgerCommand::Inspect {
            expected_ledger_digest: next.ledger_digest.clone(),
            session_id: next.session_id.clone(),
        })))
        .await;
    assert_eq!(
        structured(&inspected)
            .result
            .expect("inspect result")
            .continuation
            .expect("inspect continuation"),
        next
    );

    let read_frame = server
        .execute_tool_arguments(Some(arguments(AttentionLedgerCommand::ReadFrame {
            expected_ledger_digest: next.ledger_digest.clone(),
            frame_digest: initial.frame_digest.clone(),
        })))
        .await;
    assert_eq!(
        structured(&read_frame)
            .result
            .expect("read-frame result")
            .frame,
        Some(initial)
    );

    let read_event = server
        .execute_tool_arguments(Some(arguments(AttentionLedgerCommand::ReadEvent {
            expected_ledger_digest: next.ledger_digest.clone(),
            event_id: next.latest_event_ref.clone(),
        })))
        .await;
    assert_eq!(
        structured(&read_event)
            .result
            .expect("read-event result")
            .event
            .expect("event projection")
            .event_id,
        next.latest_event_ref
    );
    let snapshot = server.snapshot().await;
    assert_eq!(snapshot.frames.len(), 2);
    assert_eq!(snapshot.events.len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_equal_head_applies_yield_one_success_and_one_stale_refusal() {
    let ledger_id = sid("ledger:mcp-concurrency");
    let server = AttentionLedgerMcpServer::new(ledger_id.clone()).expect("server");
    let empty = new_attention_ledger(ledger_id).expect("empty mirror");
    let initial = frame();
    let opened = server
        .execute_tool_arguments(Some(arguments(AttentionLedgerCommand::Open {
            expected_ledger_digest: empty.ledger_digest,
            session_id: sid("session:mcp-concurrency"),
            frame: Box::new(initial.clone()),
        })))
        .await;
    let handle = structured(&opened)
        .result
        .expect("open result")
        .continuation
        .expect("continuation");
    let command = AttentionLedgerCommand::Apply {
        expected_ledger_digest: handle.ledger_digest,
        session_id: handle.session_id,
        expected_sequence: handle.session_sequence,
        expected_head_frame_digest: handle.head_frame_digest,
        session_operation: AttentionSessionOperation::Compact {
            compaction: Box::new(compaction(&initial)),
        },
    };
    let left = server.clone();
    let right = server.clone();
    let (first, second) = tokio::join!(
        left.execute_tool_arguments(Some(arguments(command.clone()))),
        right.execute_tool_arguments(Some(arguments(command)))
    );
    let statuses = [structured(&first).status, structured(&second).status];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == LedgerMcpStatus::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == LedgerMcpStatus::Refused)
            .count(),
        1
    );
    let snapshot = server.snapshot().await;
    assert_eq!(snapshot.events.len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn official_client_opens_then_inspects_one_volatile_session() {
    let ledger_id = sid("ledger:mcp-official");
    let empty = new_attention_ledger(ledger_id.clone()).expect("empty mirror");
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-attention-ledger-mcp")).configure(
            |command| {
                command.arg("--ledger-id").arg(ledger_id.as_str());
            },
        ),
    )
    .expect("ledger MCP subprocess starts");
    let client = ().serve(transport).await.expect("MCP initializes");
    let tools = client.list_all_tools().await.expect("tools/list succeeds");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);

    let opened = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments(
                AttentionLedgerCommand::Open {
                    expected_ledger_digest: empty.ledger_digest,
                    session_id: sid("session:mcp-official"),
                    frame: Box::new(frame()),
                },
            )),
        )
        .await
        .expect("open call succeeds");
    let opened: AttentionLedgerMcpResponse =
        serde_json::from_value(opened.structured_content.expect("open structured content"))
            .expect("typed open response");
    let handle = opened
        .result
        .expect("open result")
        .continuation
        .expect("open continuation");

    let inspected = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments(
                AttentionLedgerCommand::Inspect {
                    expected_ledger_digest: handle.ledger_digest.clone(),
                    session_id: handle.session_id.clone(),
                },
            )),
        )
        .await
        .expect("inspect call succeeds");
    let inspected: AttentionLedgerMcpResponse = serde_json::from_value(
        inspected
            .structured_content
            .expect("inspect structured content"),
    )
    .expect("typed inspect response");
    assert_eq!(
        inspected
            .result
            .expect("inspect result")
            .continuation
            .expect("inspect continuation"),
        handle
    );
    client.cancel().await.expect("client closes");
}
