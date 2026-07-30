use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cantor_core::{
    ProtocolOutcome, ProtocolResponse, SopCorpusManifest, SopDocumentInput, SopSigningKeys,
    build_sop_corpus, execute_protocol_request, verify_protocol_response_against_environment,
};
use cantor_mcp::TOOL_NAME;
use ed25519_dalek::SigningKey;
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::json;

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

#[tokio::test(flavor = "current_thread")]
async fn real_mcp_process_returns_exact_self_hosted_cantor_quote() {
    let root = workspace_root();
    let manifest_path = root.join("corpus/self_hosted/corpus.json");
    let manifest: SopCorpusManifest = serde_json::from_slice(
        &fs::read(&manifest_path).expect("tracked corpus manifest must read"),
    )
    .expect("tracked corpus manifest must decode");
    let source_root = manifest_path
        .parent()
        .expect("manifest has parent")
        .join(&manifest.source_root)
        .canonicalize()
        .expect("source root exists");
    let documents = manifest
        .documents
        .iter()
        .map(|document| SopDocumentInput {
            document_id: document.document_id.clone(),
            path: document.path.clone(),
            bytes: fs::read(source_root.join(&document.path))
                .expect("governed source must be readable"),
        })
        .collect();
    let built = build_sop_corpus(
        &manifest,
        documents,
        SopSigningKeys {
            authority: SigningKey::from_bytes(&[41_u8; 32]),
            compiler: SigningKey::from_bytes(&[43_u8; 32]),
        },
    )
    .expect("tracked self-hosted corpus must build");
    let request = built
        .requests
        .iter()
        .find(|request| request.name == "query-cantor")
        .expect("Cantor query template must be generated")
        .request
        .clone();
    let direct = execute_protocol_request(&built.environment, request.clone());
    let ProtocolOutcome::Query(result) = &direct.result else {
        panic!("self-hosted request must produce a query result");
    };
    assert!(
        result
            .verified_quotes
            .iter()
            .any(|quote| quote.text.starts_with("+ [Cantor]"))
    );

    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let environment_path = std::env::temp_dir().join(format!(
        "cantor-self-hosted-mcp-{}-{sequence}.json",
        std::process::id()
    ));
    fs::write(
        &environment_path,
        serde_json::to_vec(&built.environment).expect("environment must encode"),
    )
    .expect("temporary environment must write");

    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_cantor-mcp")).configure(|command| {
            command.arg("--environment").arg(&environment_path);
        }),
    )
    .expect("Cantor MCP subprocess must start");
    let client = ().serve(transport).await.expect("MCP initialization must pass");
    let result = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(
                json!({ "request": request })
                    .as_object()
                    .expect("tool arguments are an object")
                    .clone(),
            ),
        )
        .await
        .expect("self-hosted tools/call must succeed");
    let response: ProtocolResponse = serde_json::from_value(
        result
            .structured_content
            .expect("tool result must contain structured protocol response"),
    )
    .expect("structured result must decode");
    assert_eq!(result.is_error, Some(false));
    assert_eq!(response, direct);
    verify_protocol_response_against_environment(&built.environment, &request, &response)
        .expect("MCP response must equal pinned core execution");

    client.cancel().await.expect("MCP client must stop");
    fs::remove_file(environment_path).expect("temporary environment must be removed");
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("MCP crate is nested beneath workspace root")
        .to_path_buf()
}
