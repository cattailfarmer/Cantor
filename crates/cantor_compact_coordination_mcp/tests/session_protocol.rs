use std::collections::{BTreeMap, BTreeSet};

use cantor_compact_coordination_mcp::*;
use cantor_core::*;
use cantor_procedure_tool::{CoordinationToolContext, CoordinationToolRequest};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn context() -> CoordinationToolContext {
    let mut candidate: ProcedureCandidate = serde_json::from_str(include_str!(
        "../../cantor_core/tests/fixtures/cppe_two_process_candidate.json"
    ))
    .expect("checked candidate");
    candidate.candidate_id = sid("tool-candidate:compact-session");
    candidate.author_ref = sid("model-output:compact-session-author");
    candidate.provenance_refs = BTreeSet::from([sid("evidence:compact-session")]);
    candidate.source_digest = compute_candidate_source_digest(&candidate).expect("source digest");
    let template = AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:compact-session")]),
        validator_ref: sid("validator:compact-session"),
        policy_ref: sid("policy:compact-session"),
        aliases: BTreeSet::from(["compact-session".to_owned()]),
        permitted_invocation_context: "effectless-compact-session".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("invocation:compact-session"),
        caller_ref: sid("caller:compact-session"),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:compact-session"),
        initial_logical_time: 20,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention"),
        session_generation_ref: sid("session-generation:compact-session"),
        session_ref: sid("negotiation-session:compact-session"),
        session_purpose: "prove compact context plus checkpoint custody".to_owned(),
        frame_ref: sid("frame:compact-session"),
        frame_conditions: BTreeSet::from(["effectless".to_owned()]),
        frame_constraints: BTreeSet::from(["provider-neutral".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    };
    let lane = run_authorship_lane(&candidate, &template, &BTreeMap::new()).expect("lane");
    CoordinationToolContext::from(&lane)
}

fn registry() -> CompactCoordinationRegistry {
    new_compact_coordination_registry(sid("registry:compact-session-test")).expect("registry")
}

fn handle(response: &CompactSessionResponse) -> CompactCoordinationHandle {
    match response.result.as_ref().expect("successful result") {
        CompactSessionResult::State { handle } | CompactSessionResult::Record { handle, .. } => {
            handle.clone()
        }
    }
}

fn open_command(registry: &CompactCoordinationRegistry) -> CompactSessionCommand {
    CompactSessionCommand::Open {
        expected_registry_digest: registry.registry_digest.clone(),
        session_id: sid("session:compact-session-test"),
        context_json: serde_json::to_string(&context()).expect("context JSON"),
    }
}

fn advance_command(
    handle: &CompactCoordinationHandle,
    maximum_steps: u64,
) -> CompactSessionCommand {
    CompactSessionCommand::Advance {
        expected_registry_digest: handle.registry_digest.clone(),
        session_id: handle.session_id.clone(),
        expected_sequence: handle.sequence,
        expected_record_digest: handle.record_digest.clone(),
        maximum_steps,
    }
}

fn arguments(command: CompactSessionCommand) -> serde_json::Map<String, Value> {
    json!({ "request": command })
        .as_object()
        .expect("arguments object")
        .clone()
}

fn structured(result: &rmcp::model::CallToolResult) -> CompactSessionResponse {
    serde_json::from_value(
        result
            .structured_content
            .clone()
            .expect("structured response"),
    )
    .expect("typed response")
}

#[test]
fn pure_open_advance_inspect_read_and_terminal_match_stateless_core() {
    let initial = registry();
    let opened = apply_compact_coordination_command(&initial, open_command(&initial));
    assert_eq!(opened.response.status, CompactResponseStatus::Succeeded);
    let first = handle(&opened.response);
    assert_eq!(first.sequence, 1);
    assert_eq!(first.status, CompactSessionStatus::Ready);

    let advanced =
        apply_compact_coordination_command(&opened.successor, advance_command(&first, 8));
    let second = handle(&advanced.response);
    assert_eq!(second.sequence, 2);
    assert_eq!(second.status, CompactSessionStatus::Ready);
    let terminal =
        apply_compact_coordination_command(&advanced.successor, advance_command(&second, 8));
    let terminal_handle = handle(&terminal.response);
    assert_eq!(terminal_handle.sequence, 3);
    assert_eq!(terminal_handle.status, CompactSessionStatus::Terminal);

    let inspected = apply_compact_coordination_command(
        &terminal.successor,
        CompactSessionCommand::Inspect {
            expected_registry_digest: terminal_handle.registry_digest.clone(),
            session_id: terminal_handle.session_id.clone(),
        },
    );
    assert_eq!(inspected.successor, terminal.successor);
    assert_eq!(handle(&inspected.response), terminal_handle);

    let read = apply_compact_coordination_command(
        &terminal.successor,
        CompactSessionCommand::Read {
            expected_registry_digest: terminal_handle.registry_digest.clone(),
            session_id: terminal_handle.session_id.clone(),
        },
    );
    let record_json = match read.response.result.expect("read result") {
        CompactSessionResult::Record { record_json, .. } => record_json,
        CompactSessionResult::State { .. } => panic!("expected record"),
    };
    let record: CompactCoordinationRecord =
        serde_json::from_str(&record_json).expect("exact record JSON");
    let outcome = record.outcome.expect("terminal outcome");

    let direct_context = context();
    let begin =
        cantor_procedure_tool::execute_coordination_tool_request(CoordinationToolRequest::Begin {
            context: Box::new(direct_context.clone()),
        });
    let checkpoint = match begin.result.expect("begin result") {
        cantor_procedure_tool::CoordinationToolResult::Began { checkpoint } => checkpoint,
        _ => panic!("expected begin"),
    };
    let first_direct = cantor_procedure_tool::execute_coordination_tool_request(
        CoordinationToolRequest::Advance {
            context: Box::new(direct_context.clone()),
            checkpoint,
            maximum_steps: 8,
        },
    );
    let checkpoint = match first_direct.result.expect("first advance") {
        cantor_procedure_tool::CoordinationToolResult::Advanced { transition } => {
            Box::new(transition.checkpoint.expect("paused checkpoint"))
        }
        _ => panic!("expected advance"),
    };
    let final_direct = cantor_procedure_tool::execute_coordination_tool_request(
        CoordinationToolRequest::Advance {
            context: Box::new(direct_context),
            checkpoint,
            maximum_steps: 8,
        },
    );
    let direct_outcome = match final_direct.result.expect("terminal advance") {
        cantor_procedure_tool::CoordinationToolResult::Advanced { transition } => {
            transition.outcome.expect("terminal outcome")
        }
        _ => panic!("expected advance"),
    };
    assert_eq!(*outcome, direct_outcome);
}

#[test]
fn stale_duplicate_zero_quota_terminal_and_corrupt_states_fail_without_mutation() {
    let initial = registry();
    let opened = apply_compact_coordination_command(&initial, open_command(&initial));
    let first = handle(&opened.response);

    let duplicate = apply_compact_coordination_command(
        &opened.successor,
        CompactSessionCommand::Open {
            expected_registry_digest: opened.successor.registry_digest.clone(),
            session_id: first.session_id.clone(),
            context_json: serde_json::to_string(&context()).expect("context JSON"),
        },
    );
    assert_eq!(duplicate.successor, opened.successor);
    assert_eq!(duplicate.response.status, CompactResponseStatus::Refused);

    let zero = apply_compact_coordination_command(&opened.successor, advance_command(&first, 0));
    assert_eq!(zero.successor, opened.successor);
    assert_eq!(zero.response.status, CompactResponseStatus::InvalidRequest);

    let advanced =
        apply_compact_coordination_command(&opened.successor, advance_command(&first, 64));
    let terminal_handle = handle(&advanced.response);
    let terminal = apply_compact_coordination_command(
        &advanced.successor,
        advance_command(&terminal_handle, 1),
    );
    assert_eq!(terminal.successor, advanced.successor);
    assert_eq!(terminal.response.status, CompactResponseStatus::Refused);

    let stale = apply_compact_coordination_command(&advanced.successor, advance_command(&first, 1));
    assert_eq!(stale.successor, advanced.successor);
    assert_eq!(stale.response.status, CompactResponseStatus::Refused);

    let mut corrupt = advanced.successor;
    corrupt.generation += 1;
    assert!(validate_compact_coordination_registry(&corrupt).is_err());
}

#[test]
fn compact_tool_schema_and_advance_payload_are_materially_smaller_than_stateless_baseline() {
    let tool = CompactCoordinationMcpServer::tool_definition();
    let metadata_bytes = serde_json::to_vec(&tool).expect("metadata").len();
    assert!(metadata_bytes < 16_000, "metadata bytes {metadata_bytes}");
    let initial = registry();
    let opened = apply_compact_coordination_command(&initial, open_command(&initial));
    let current = handle(&opened.response);
    let payload_bytes = serde_json::to_vec(&json!({
        "request": advance_command(&current, 8)
    }))
    .expect("advance payload")
    .len();
    println!("compact_metadata_bytes={metadata_bytes} compact_advance_bytes={payload_bytes}");
    assert!(payload_bytes < 1_000, "advance bytes {payload_bytes}");
    assert!(
        !serde_json::to_string(&tool)
            .expect("tool JSON")
            .contains("ProcedureCatalogueState")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_equal_head_advances_admit_exactly_one_successor() {
    let server =
        CompactCoordinationMcpServer::new(sid("registry:compact-concurrency")).expect("server");
    let initial = server.snapshot().await;
    let opened = server
        .execute_tool_arguments(Some(arguments(open_command(&initial))))
        .await;
    let current = handle(&structured(&opened));
    let command = advance_command(&current, 8);
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
            .filter(|status| **status == CompactResponseStatus::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == CompactResponseStatus::Refused)
            .count(),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_oversized_and_restart_reentry_fail_closed() {
    let server =
        CompactCoordinationMcpServer::new(sid("registry:compact-boundary")).expect("server");
    let initial = server.snapshot().await;
    let malformed = server
        .execute_tool_arguments(Some(
            json!({ "request": open_command(&initial), "invented_authority": true })
                .as_object()
                .expect("arguments")
                .clone(),
        ))
        .await;
    assert_eq!(
        structured(&malformed).status,
        CompactResponseStatus::InvalidRequest
    );
    assert_eq!(server.snapshot().await, initial);

    let oversized = server
        .execute_tool_arguments(Some(
            json!({ "padding": "x".repeat(MAX_ARGUMENT_BYTES) })
                .as_object()
                .expect("arguments")
                .clone(),
        ))
        .await;
    assert_eq!(
        structured(&oversized).status,
        CompactResponseStatus::InvalidRequest
    );
    assert_eq!(server.snapshot().await, initial);

    let opened = server
        .execute_tool_arguments(Some(arguments(open_command(&initial))))
        .await;
    let old_handle = handle(&structured(&opened));
    let restarted = CompactCoordinationMcpServer::new(sid("registry:compact-boundary"))
        .expect("restarted server");
    let refused = restarted
        .execute_tool_arguments(Some(arguments(CompactSessionCommand::Inspect {
            expected_registry_digest: old_handle.registry_digest,
            session_id: old_handle.session_id,
        })))
        .await;
    assert_eq!(structured(&refused).status, CompactResponseStatus::Refused);
    assert!(restarted.snapshot().await.sessions.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn official_client_opens_and_inspects_one_volatile_session() {
    let initial = new_compact_coordination_registry(sid(DEFAULT_REGISTRY_ID)).expect("initial");
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-compact-coordination-mcp"))
            .configure(|_| {}),
    )
    .expect("subprocess starts");
    let client = ().serve(transport).await.expect("MCP initializes");
    let tools = client.list_all_tools().await.expect("tools/list");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);
    let opened = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments(open_command(&initial))),
        )
        .await
        .expect("OPEN call");
    let opened: CompactSessionResponse =
        serde_json::from_value(opened.structured_content.expect("structured OPEN"))
            .expect("typed OPEN");
    let current = handle(&opened);
    let inspected = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments(
                CompactSessionCommand::Inspect {
                    expected_registry_digest: current.registry_digest.clone(),
                    session_id: current.session_id.clone(),
                },
            )),
        )
        .await
        .expect("INSPECT call");
    let inspected: CompactSessionResponse =
        serde_json::from_value(inspected.structured_content.expect("structured INSPECT"))
            .expect("typed INSPECT");
    assert_eq!(handle(&inspected), current);
    client.cancel().await.expect("client closes");
}
