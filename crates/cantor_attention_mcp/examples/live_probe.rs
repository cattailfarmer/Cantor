use std::env;

use cantor_attention_mcp::{
    ATTENTION_FRAME_PROFILE, FRAME_RESULT_PROFILE, SERVER_INSTRUCTIONS, TOOL_NAME,
};
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("live_probe: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let separator = arguments
        .iter()
        .position(|value| value == "--stimulus")
        .ok_or("usage: live_probe <server-program> [server-args...] --stimulus <text> [--response-mode full|frame]")?;
    if separator == 0 || separator + 2 > arguments.len() {
        return Err("usage: live_probe <server-program> [server-args...] --stimulus <text> [--response-mode full|frame]".into());
    }
    let program = &arguments[0];
    let server_arguments = &arguments[1..separator];
    let stimulus = &arguments[separator + 1];
    let response_mode = match &arguments[separator + 2..] {
        [] => None,
        [flag, mode] if flag == "--response-mode" => Some(mode.as_str()),
        _ => return Err("invalid live_probe response mode arguments".into()),
    };
    let transport =
        TokioChildProcess::new(tokio::process::Command::new(program).configure(|command| {
            command.args(server_arguments);
        }))?;
    let client = ().serve(transport).await?;
    let peer = client
        .peer_info()
        .ok_or("server initialization omitted peer information")?;
    if peer.instructions.as_deref() != Some(SERVER_INSTRUCTIONS) {
        return Err("server initialization instructions differ from the governed surface".into());
    }
    let tools = client.list_all_tools().await?;
    if tools.len() != 1 || tools[0].name != TOOL_NAME {
        return Err("server did not publish the exact route_attention surface".into());
    }
    let mut tool_arguments = json!({ "stimulus": stimulus })
        .as_object()
        .ok_or("tool arguments must be an object")?
        .clone();
    if let Some(response_mode) = response_mode {
        tool_arguments.insert("response_mode".to_owned(), json!(response_mode));
    }
    let result = client
        .call_tool(CallToolRequestParams::new(TOOL_NAME).with_arguments(tool_arguments))
        .await?;
    let structured = result
        .structured_content
        .as_ref()
        .ok_or("tool result omitted structuredContent")?;
    let is_error = result.is_error == Some(true);
    if !is_error {
        let frame = structured
            .get("attention_frame")
            .ok_or("selected result omitted attention_frame")?;
        if frame.get("profile").and_then(serde_json::Value::as_str) != Some(ATTENTION_FRAME_PROFILE)
        {
            return Err("selected attention_frame profile differs".into());
        }
        if structured
            .get("profile")
            .and_then(serde_json::Value::as_str)
            == Some(FRAME_RESULT_PROFILE)
        {
            if frame
                .pointer("/sequence/2/basis")
                .and_then(serde_json::Value::as_str)
                != Some("verified_admission_account")
                || !frame
                    .pointer("/sequence/3/evidence_id")
                    .is_some_and(serde_json::Value::is_string)
                || !frame
                    .pointer("/sequence/3/manifest_sha256")
                    .is_some_and(serde_json::Value::is_string)
            {
                return Err("compact attention_frame omits its verified evidence reference".into());
            }
        } else if frame.pointer("/sequence/0/procedure_id")
            != structured.pointer("/runtime/procedure_id")
            || frame.pointer("/sequence/3/evidence_id") != structured.pointer("/runtime/run_id")
            || frame.pointer("/sequence/3/manifest_sha256")
                != structured.pointer("/verification/manifest_sha256")
        {
            return Err("selected attention_frame is not relationally bound".into());
        }
    } else if structured.get("attention_frame").is_some() {
        return Err("fault result carried a positive attention_frame".into());
    }
    println!("{}", serde_json::to_string(structured)?);
    client.cancel().await?;
    if is_error {
        std::process::exit(4);
    }
    Ok(())
}
