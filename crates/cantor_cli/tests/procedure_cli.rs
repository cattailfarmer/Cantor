use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use cantor_core::*;
use serde_json::{Value, json};

static FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn sid(value: &str) -> SemanticId {
    SemanticId::new(value).expect("fixture identity")
}

fn model_candidate() -> ProcedureCandidate {
    let mut candidate: ProcedureCandidate = serde_json::from_str(include_str!(
        "../../cantor_core/tests/fixtures/cppe_two_process_candidate.json"
    ))
    .expect("checked two-process candidate fixture");
    candidate.candidate_id = sid("tool-candidate:cli-model-shaped");
    candidate.author_ref = sid("model-output:cli-tool-procedure-author");
    candidate.provenance_refs = BTreeSet::from([sid("evidence:cli-model-shaped-tool-output")]);
    candidate.source_digest =
        compute_candidate_source_digest(&candidate).expect("candidate source digest");
    candidate
}

fn model_template() -> AuthorshipLaneTemplate {
    AuthorshipLaneTemplate {
        class: AuthorshipClass::ModelShaped,
        authorship_evidence_refs: BTreeSet::from([sid("evidence:cli-model-shaped-tool-output")]),
        validator_ref: sid("validator:independent-cli-tool-fixture"),
        policy_ref: sid("policy:cli-tool-fixture"),
        aliases: BTreeSet::from(["cli-tool-fixture".to_owned()]),
        permitted_invocation_context: "effectless-cli-tool-controller".to_owned(),
        revocation_conditions: BTreeSet::from(["identity changes".to_owned()]),
        invocation_ref: sid("tool-invocation:cli-model-shaped"),
        caller_ref: sid("caller:fake-cli-model-controller"),
        input: ProcedureValue::Record {
            fields: BTreeMap::from([(
                "subject".to_owned(),
                ProcedureValue::Text {
                    value: "hello".to_owned(),
                },
            )]),
        },
        input_sensitivity: SensitivityClass::ProjectInternal,
        sop_generation_ref: sid("sop-generation:cli-tool-fixture"),
        initial_logical_time: 20,
        budgets: InvocationBudget {
            logical_time_limit: 64,
            step_limit: 64,
            memory_unit_limit: 16_384,
            message_limit: 16,
            trace_event_limit: 128,
        },
        retention_policy_ref: sid("policy:retention"),
        session_generation_ref: sid("tool-session-generation:cli-model-shaped"),
        session_ref: sid("tool-session:cli-model-shaped"),
        session_purpose: "prove the subprocess experiment adapter".to_owned(),
        frame_ref: sid("tool-frame:cli-model-shaped"),
        frame_conditions: BTreeSet::from(["effectless".to_owned()]),
        frame_constraints: BTreeSet::from(["provider-neutral".to_owned()]),
        permitted_message_kinds: BTreeSet::from([
            ProcedureMessageKind::Propose,
            ProcedureMessageKind::Support,
            ProcedureMessageKind::Pass,
        ]),
    }
}

fn lane() -> AuthorshipLaneEvidence {
    run_authorship_lane(&model_candidate(), &model_template(), &BTreeMap::new())
        .expect("CLI tool lane")
}

fn proposal(schema: &ProviderNeutralToolSchema, lane: &AuthorshipLaneEvidence) -> ToolCallProposal {
    let mut proposal = ToolCallProposal {
        schema_ref: schema.schema_id.clone(),
        schema_digest: schema.schema_digest.clone(),
        call_id: sid("tool-call:cli-reconcile-1"),
        inference_job_ref: sid("inference-job:cli-fake-controller-1"),
        participant_ref: lane.request.caller_ref.clone(),
        pass_index: 3,
        operation: ExchangeOperation::Reconcile,
        invocation: lane.request.clone(),
        session: lane.initial_session.clone(),
        argument_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: String::new(),
        },
    };
    proposal.argument_digest =
        compute_tool_call_argument_digest(&proposal).expect("tool argument digest");
    proposal
}

fn run_request() -> (
    ProviderNeutralToolSchema,
    ToolCallProposal,
    AuthorshipLaneEvidence,
    Value,
) {
    let schema = provider_neutral_exchange_schema().expect("schema");
    let lane = lane();
    let proposal = proposal(&schema, &lane);
    let request = json!({
        "schema": schema,
        "proposal": proposal,
        "lane": lane,
    });
    (schema, proposal, lane, request)
}

fn execute(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cantor-procedure-experiment"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn procedure experiment CLI");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(input)
        .expect("write child stdin");
    child.wait_with_output().expect("collect CLI output")
}

fn response(output: &Output) -> Value {
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    serde_json::from_slice(&output.stdout).expect("stdout must be one JSON response")
}

#[test]
fn schema_matches_the_direct_core_and_declares_residuals() {
    let output = execute(&["schema"], b"");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let value = response(&output);
    assert_eq!(value["status"], "success");
    assert_eq!(value["grade"], "effectless_internal_experiment_only");
    assert_eq!(
        serde_json::from_value::<ProviderNeutralToolSchema>(value["schema"].clone())
            .expect("schema response"),
        provider_neutral_exchange_schema().expect("direct schema")
    );
    assert_eq!(value["residuals"].as_array().expect("residuals").len(), 3);
    assert!(value.get("prepared_request").is_none());
}

#[test]
fn stdin_run_is_direct_core_equivalent_and_byte_deterministic() {
    let (schema, proposal, lane, request) = run_request();
    let bytes = serde_json::to_vec(&request).expect("request JSON");
    let first = execute(&["run"], &bytes);
    let second = execute(&["run"], &bytes);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let value = response(&first);
    assert!(value.get("prepared_request").is_none());
    let outcome: FakeControllerOutcome =
        serde_json::from_value(value["outcome"].clone()).expect("outcome");
    assert_eq!(
        outcome,
        run_fake_controller_exchange(&schema, &proposal, &lane).expect("direct outcome")
    );
    verify_fake_controller_outcome(&schema, &proposal, &lane, &outcome)
        .expect("CLI outcome verifies");
}

#[test]
fn prepare_is_direct_lane_equivalent_deterministic_and_run_compatible() {
    let candidate = model_candidate();
    let template = model_template();
    let expected_lane =
        run_authorship_lane(&candidate, &template, &BTreeMap::new()).expect("direct prepared lane");
    let request = json!({
        "candidate": candidate,
        "template": template,
        "recognized_anchors": {},
        "call_id": "tool-call:prepared-cli-1",
        "inference_job_ref": "inference-job:prepared-cli-1",
        "pass_index": 7,
    });
    let bytes = serde_json::to_vec(&request).expect("prepare request");
    let first = execute(&["prepare"], &bytes);
    let second = execute(&["prepare"], &bytes);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
    assert!(first.stderr.is_empty());
    let value = response(&first);
    assert_eq!(value["profile"], "cantor-procedure-tool-preparation/0.1");
    let prepared = value["prepared_request"].clone();
    assert_eq!(
        serde_json::from_value::<AuthorshipLaneEvidence>(prepared["lane"].clone())
            .expect("prepared lane"),
        expected_lane
    );
    let proposal: ToolCallProposal =
        serde_json::from_value(prepared["proposal"].clone()).expect("prepared proposal");
    assert_eq!(proposal.operation, ExchangeOperation::Reconcile);
    assert_eq!(proposal.participant_ref, expected_lane.request.caller_ref);
    assert_eq!(
        compute_tool_call_argument_digest(&proposal).expect("argument digest"),
        proposal.argument_digest
    );

    let run = execute(
        &["run"],
        &serde_json::to_vec(&prepared).expect("prepared run request"),
    );
    assert_eq!(run.status.code(), Some(0));
    assert_eq!(response(&run)["status"], "success");
}

#[test]
fn prepare_refuses_invalid_lane_and_invalid_envelope_without_partial_output() {
    let candidate = model_candidate();
    let mut invalid_template = model_template();
    invalid_template
        .authorship_evidence_refs
        .insert(sid("evidence:absent"));
    let request = json!({
        "candidate": candidate,
        "template": invalid_template,
        "recognized_anchors": {},
        "call_id": "tool-call:prepared-cli-invalid",
        "inference_job_ref": "inference-job:prepared-cli-invalid",
        "pass_index": 7,
    });
    let refused = execute(
        &["prepare"],
        &serde_json::to_vec(&request).expect("invalid lane request"),
    );
    assert_eq!(refused.status.code(), Some(3));
    let value = response(&refused);
    assert_eq!(value["faults"][0]["code"], "lane_preparation_refused");
    assert!(value.get("prepared_request").is_none());

    let mut unknown = request.clone();
    unknown["ambient_authority"] = json!(true);
    let invalid = execute(
        &["prepare"],
        &serde_json::to_vec(&unknown).expect("unknown-field request"),
    );
    assert_eq!(invalid.status.code(), Some(2));
    assert!(response(&invalid).get("prepared_request").is_none());

    let mut exhausted = request;
    exhausted["candidate"] = serde_json::to_value(model_candidate()).expect("candidate");
    exhausted["pass_index"] = json!(u64::MAX);
    let invalid = execute(
        &["prepare"],
        &serde_json::to_vec(&exhausted).expect("exhausted request"),
    );
    assert_eq!(invalid.status.code(), Some(2));
    let value = response(&invalid);
    assert_eq!(value["faults"][0]["code"], "pass_index_exhausted");
    assert!(value.get("prepared_request").is_none());
}

#[test]
fn file_input_and_verified_refusal_remain_machine_visible() {
    let (schema, mut proposal, lane, _) = run_request();
    proposal.operation = ExchangeOperation::Challenge;
    proposal.argument_digest =
        compute_tool_call_argument_digest(&proposal).expect("changed proposal digest");
    let request = json!({ "schema": schema, "proposal": proposal, "lane": lane });
    let path = std::env::temp_dir().join(format!(
        "cantor-procedure-cli-{}-{}.json",
        std::process::id(),
        FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, serde_json::to_vec(&request).expect("request JSON"))
        .expect("write input fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_cantor-procedure-experiment"))
        .args(["run", "--input", path.to_str().expect("UTF-8 path")])
        .output()
        .expect("run file input");
    std::fs::remove_file(path).expect("remove input fixture");
    assert_eq!(output.status.code(), Some(3));
    assert!(!output.stderr.is_empty());
    let value = response(&output);
    assert_eq!(value["status"], "refused");
    assert_eq!(value["faults"][0]["code"], "operation_not_executable");
    let outcome: FakeControllerOutcome =
        serde_json::from_value(value["outcome"].clone()).expect("refused outcome");
    let schema: ProviderNeutralToolSchema =
        serde_json::from_value(request["schema"].clone()).expect("schema");
    let proposal: ToolCallProposal =
        serde_json::from_value(request["proposal"].clone()).expect("proposal");
    let lane: AuthorshipLaneEvidence =
        serde_json::from_value(request["lane"].clone()).expect("lane");
    verify_fake_controller_outcome(&schema, &proposal, &lane, &outcome).expect("refusal verifies");
}

#[test]
fn verify_accepts_exact_outcome_and_rejects_tampering() {
    let (schema, proposal, lane, _) = run_request();
    let outcome = run_fake_controller_exchange(&schema, &proposal, &lane).expect("outcome");
    let valid = json!({
        "schema": schema,
        "proposal": proposal,
        "lane": lane,
        "outcome": outcome,
    });
    let output = execute(
        &["verify"],
        &serde_json::to_vec(&valid).expect("verify JSON"),
    );
    assert_eq!(output.status.code(), Some(0));
    let value = response(&output);
    assert_eq!(value["verification"]["verified"], true);
    assert_eq!(
        value["verification"]["result_digest"],
        valid["outcome"]["result"]["result_digest"]
    );

    let mut tampered = valid;
    tampered["outcome"]["result"]["residuals"] = json!(["unbound claim"]);
    let output = execute(
        &["verify"],
        &serde_json::to_vec(&tampered).expect("tampered JSON"),
    );
    assert_eq!(output.status.code(), Some(4));
    let value = response(&output);
    assert_eq!(value["status"], "verification_failure");
    assert_eq!(value["faults"][0]["code"], "outcome_verification_failed");
    assert!(value["outcome"].is_null());
}

#[test]
fn invalid_ingress_fails_closed_with_one_machine_response() {
    let malformed = execute(&["run"], b"{not-json");
    assert_eq!(malformed.status.code(), Some(2));
    assert_eq!(
        response(&malformed)["faults"][0]["code"],
        "invalid_request_json"
    );

    let (_, _, _, mut unknown) = run_request();
    unknown["unexpected"] = json!(true);
    let unknown = execute(
        &["run"],
        &serde_json::to_vec(&unknown).expect("unknown-field JSON"),
    );
    assert_eq!(unknown.status.code(), Some(2));
    assert_eq!(response(&unknown)["status"], "invalid_input");

    let empty = execute(&["verify"], b"");
    assert_eq!(empty.status.code(), Some(2));
    assert_eq!(response(&empty)["faults"][0]["code"], "empty_input");

    let unknown_command = execute(&["join"], b"");
    assert_eq!(unknown_command.status.code(), Some(2));
    assert_eq!(response(&unknown_command)["operation"], "join");

    let duplicate = execute(&["run", "--input", "a", "--input", "b"], b"");
    assert_eq!(duplicate.status.code(), Some(2));
    assert_eq!(
        response(&duplicate)["faults"][0]["code"],
        "invalid_arguments"
    );

    let oversized = execute(&["run"], &vec![b'x'; 16 * 1024 * 1024 + 1]);
    assert_eq!(oversized.status.code(), Some(2));
    assert_eq!(
        response(&oversized)["faults"][0]["code"],
        "input_limit_exceeded"
    );
}
