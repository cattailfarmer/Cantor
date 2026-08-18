use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use cantor_attention_mcp::{AttentionMcpConfig, AttentionMcpServer, TOOL_NAME};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, JsonObject},
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const DEPLOYMENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CATALOGUE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct Fixture {
    root: PathBuf,
    controller: PathBuf,
    config: AttentionMcpConfig,
    config_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must follow epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "cantor-attention-mcp-test-{}-{sequence}-{epoch}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("fixture root must be unique");
        let controller = root.join("fake_runtime.py");
        fs::write(&controller, FAKE_RUNTIME).expect("fake controller must write");
        let runtime_config = root.join("runtime.json");
        fs::write(
            &runtime_config,
            serde_json::to_vec(&json!({
                "deployment_manifest_sha256": DEPLOYMENT
            }))
            .expect("runtime config must encode"),
        )
        .expect("runtime config must write");
        let python = python_path();
        let config = AttentionMcpConfig {
            profile: "cantor-route-attention-mcp-config/0.1".to_owned(),
            python,
            controller: controller.clone(),
            runtime_config: runtime_config.clone(),
            expected_controller_sha256: digest_file(&controller),
            expected_runtime_config_sha256: digest_file(&runtime_config),
            expected_deployment_manifest_sha256: DEPLOYMENT.to_owned(),
            expected_catalogue_digest: CATALOGUE.to_owned(),
            timeout_milliseconds: 10_000,
            max_input_bytes: 64,
            max_output_bytes: 65_536,
        };
        let config_path = root.join("adapter.json");
        fs::write(
            &config_path,
            serde_json::to_vec(&json!({
                "profile": config.profile,
                "python": config.python,
                "controller": config.controller,
                "runtime_config": config.runtime_config,
                "expected_controller_sha256": config.expected_controller_sha256,
                "expected_runtime_config_sha256": config.expected_runtime_config_sha256,
                "expected_deployment_manifest_sha256": config.expected_deployment_manifest_sha256,
                "expected_catalogue_digest": config.expected_catalogue_digest,
                "timeout_milliseconds": config.timeout_milliseconds,
                "max_input_bytes": config.max_input_bytes,
                "max_output_bytes": config.max_output_bytes
            }))
            .expect("adapter config must encode"),
        )
        .expect("adapter config must write");
        Self {
            root,
            controller,
            config,
            config_path,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn python_path() -> PathBuf {
    let output = StdCommand::new("python")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("Python is required by the runtime fixture");
    assert!(output.status.success());
    PathBuf::from(
        String::from_utf8(output.stdout)
            .expect("Python path must be UTF-8")
            .trim(),
    )
}

fn digest_file(path: &Path) -> String {
    Sha256::digest(fs::read(path).expect("fixture file must read"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn arguments(stimulus: &str) -> JsonObject {
    json!({ "stimulus": stimulus })
        .as_object()
        .expect("arguments are an object")
        .clone()
}

fn structured(result: &rmcp::model::CallToolResult) -> &Value {
    result
        .structured_content
        .as_ref()
        .expect("tool result must be structured")
}

#[tokio::test(flavor = "current_thread")]
async fn direct_tool_is_separate_verified_and_fail_closed() {
    let fixture = Fixture::new();
    let server = AttentionMcpServer::new(fixture.config.clone())
        .await
        .expect("pinned fake runtime must pass health");
    let tool = serde_json::to_value(AttentionMcpServer::tool_definition())
        .expect("tool definition must encode");
    assert_eq!(tool["name"], TOOL_NAME);
    assert_eq!(tool["annotations"]["readOnlyHint"], true);
    assert_eq!(tool["annotations"]["destructiveHint"], false);
    assert_eq!(tool["annotations"]["idempotentHint"], false);

    let selected = server
        .execute_tool_arguments(Some(arguments("cantor")))
        .await;
    assert_eq!(selected.is_error, Some(false));
    assert_eq!(structured(&selected)["status"], "route_selected");
    assert_eq!(
        structured(&selected)["verification"]["admission_account"],
        "verified"
    );
    assert_eq!(
        structured(&selected)["authority"],
        "learned_evidence_backed_proposal"
    );

    let refused = server
        .execute_tool_arguments(Some(arguments("refuse")))
        .await;
    assert_eq!(refused.is_error, Some(true));
    assert_eq!(structured(&refused)["fault"]["code"], "runtime_refused");
    assert_eq!(
        structured(&refused)["runtime"]["fault"]["code"],
        "needle_no_tool_call"
    );
    assert_eq!(
        structured(&refused)["verification"]["recorded_status"],
        "fault"
    );
    assert_eq!(
        structured(&refused)["verification"]["admission_account"],
        "not_applicable"
    );

    let no_evidence = server
        .execute_tool_arguments(Some(arguments("noevidence")))
        .await;
    assert_eq!(no_evidence.is_error, Some(true));
    assert!(structured(&no_evidence).get("verification").is_none());

    let bad_negative = server
        .execute_tool_arguments(Some(arguments("badnegative")))
        .await;
    assert_eq!(bad_negative.is_error, Some(true));
    assert_eq!(
        structured(&bad_negative)["fault"]["code"],
        "evidence_verification_failed"
    );

    let unverifiable = server
        .execute_tool_arguments(Some(arguments("badverify")))
        .await;
    assert_eq!(unverifiable.is_error, Some(true));
    assert_eq!(
        structured(&unverifiable)["fault"]["code"],
        "evidence_verification_failed"
    );

    let malformed_output = server
        .execute_tool_arguments(Some(arguments("malformed")))
        .await;
    assert_eq!(malformed_output.is_error, Some(true));
    assert_eq!(
        structured(&malformed_output)["fault"]["code"],
        "runtime_output_invalid"
    );

    let malformed = server
        .execute_tool_arguments(Some(
            json!({ "stimulus": "cantor", "authority": true })
                .as_object()
                .expect("malformed arguments are an object")
                .clone(),
        ))
        .await;
    assert_eq!(structured(&malformed)["fault"]["code"], "invalid_arguments");
}

#[tokio::test(flavor = "current_thread")]
async fn route_timeout_is_typed_and_kills_the_child() {
    let mut fixture = Fixture::new();
    fixture.config.timeout_milliseconds = 50;
    let server = AttentionMcpServer::new(fixture.config.clone())
        .await
        .expect("fast health must pass under the short route timeout");
    let result = server.execute_tool_arguments(Some(arguments("slow"))).await;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(structured(&result)["fault"]["code"], "runtime_timeout");
}

#[tokio::test(flavor = "current_thread")]
async fn post_start_controller_drift_is_detected_before_execution() {
    let fixture = Fixture::new();
    let server = AttentionMcpServer::new(fixture.config.clone())
        .await
        .expect("pinned fake runtime must pass health");
    fs::write(&fixture.controller, format!("{FAKE_RUNTIME}\n# drift"))
        .expect("controlled drift must write");
    let result = server
        .execute_tool_arguments(Some(arguments("cantor")))
        .await;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        structured(&result)["fault"]["code"],
        "artifact_identity_mismatch"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn official_mcp_client_initializes_lists_calls_and_recovers() {
    let fixture = Fixture::new();
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-attention-mcp")).configure(
            |command| {
                command.arg("--config").arg(&fixture.config_path);
            },
        ),
    )
    .expect("attention MCP subprocess must start");
    let client = ().serve(transport).await.expect("MCP initialization must pass");
    let tools = client.list_all_tools().await.expect("tools/list must pass");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, TOOL_NAME);
    let result = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments("cantor")))
        .await
        .expect("tools/call must pass");
    assert_eq!(
        result.is_error,
        Some(false),
        "unexpected result: {:?}; trace: {:?}",
        result.structured_content,
        fs::read_to_string(fixture.controller.with_extension("log"))
    );
    assert_eq!(structured(&result)["status"], "route_selected");
    let malformed = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(JsonObject::default()))
        .await
        .expect("malformed call remains visible");
    assert_eq!(malformed.is_error, Some(true));
    let recovered = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments("cantor")))
        .await
        .expect("server must recover after caller fault");
    assert_eq!(recovered.is_error, Some(false));
    client.cancel().await.expect("MCP client must stop");
}

const FAKE_RUNTIME: &str = r#"import json
import sys
import time

PROFILE = "cantor-needle-runtime-result/0.2"
DEPLOYMENT = "1111111111111111111111111111111111111111111111111111111111111111"
CATALOGUE = "2222222222222222222222222222222222222222222222222222222222222222"
DIGEST = "3333333333333333333333333333333333333333333333333333333333333333"
RUN_ID = "12345678-1234-1234-1234-123456789abc"
BAD_RUN_ID = "12345678-1234-1234-1234-123456789def"
REFUSAL_RUN_ID = "12345678-1234-1234-1234-123456789fed"
BAD_NEGATIVE_RUN_ID = "12345678-1234-1234-1234-123456789f00"

args = sys.argv[1:]
command = next(value for value in args if value in ("health", "run", "verify"))
with open(__file__.rsplit(".", 1)[0] + ".log", "a", encoding="utf-8") as trace:
    trace.write(command + " " + repr(args) + "\n")
if command == "health":
    value = {
        "profile": PROFILE,
        "status": "healthy",
        "catalogue_digest": CATALOGUE,
        "deployment": {"manifest_sha256": DEPLOYMENT},
    }
elif command == "run":
    stimulus = args[args.index("--text") + 1]
    if stimulus == "slow":
        time.sleep(1)
    if stimulus == "malformed":
        print("not-json")
        raise SystemExit(0)
    if stimulus in ("refuse", "noevidence", "badnegative"):
        detail = {}
        if stimulus == "refuse":
            detail["run_id"] = REFUSAL_RUN_ID
        elif stimulus == "badnegative":
            detail["run_id"] = BAD_NEGATIVE_RUN_ID
        value = {
            "profile": PROFILE,
            "status": "fault",
            "fault": {
                "code": "needle_no_tool_call",
                "message": "no route",
                "detail": detail,
            },
        }
        print(json.dumps(value, separators=(",", ":")))
        raise SystemExit(2)
    value = {
        "profile": PROFILE,
        "status": "route_selected",
        "run_id": BAD_RUN_ID if stimulus == "badverify" else RUN_ID,
        "procedure_id": "attention.resolve_sop_subject",
        "procedure_digest": DIGEST,
        "catalogue_digest": CATALOGUE,
        "admission_account": {"profile": "cantor-attention-admission-account/0.1"},
        "admission_account_digest": DIGEST,
    }
else:
    requested_id = args[args.index("--id") + 1]
    negative = requested_id in (REFUSAL_RUN_ID, BAD_NEGATIVE_RUN_ID)
    value = {
        "profile": PROFILE,
        "status": "verified",
        "evidence_kind": "run",
        "evidence_id": requested_id,
        "recorded_status": "fault" if negative else "route_selected",
        "admission_account": (
            "not_applicable" if requested_id == REFUSAL_RUN_ID
            else "verified" if requested_id == BAD_NEGATIVE_RUN_ID
            else "legacy_absent" if requested_id == BAD_RUN_ID
            else "verified"
        ),
        "manifest_sha256": DIGEST,
    }
print(json.dumps(value, separators=(",", ":")))
"#;
