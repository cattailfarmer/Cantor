use std::env;

use cantor_attention_mcp::{FRAME_RESULT_PROFILE, TOOL_NAME};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("live_concurrency_probe: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let first_marker = arguments
        .iter()
        .position(|value| value == "--first")
        .ok_or("usage: live_concurrency_probe <server-program> [server-args...] --first <text> --second <text> [--response-mode full|frame]")?;
    if first_marker == 0 || arguments.get(first_marker + 2).map(String::as_str) != Some("--second")
    {
        return Err("usage: live_concurrency_probe <server-program> [server-args...] --first <text> --second <text> [--response-mode full|frame]".into());
    }
    let program = &arguments[0];
    let server_arguments = &arguments[1..first_marker];
    let first_stimulus = &arguments[first_marker + 1];
    let second_stimulus = &arguments[first_marker + 3];
    let response_mode = match &arguments[first_marker + 4..] {
        [] => None,
        [flag, mode] if flag == "--response-mode" => Some(mode.as_str()),
        _ => return Err("invalid live_concurrency_probe response mode arguments".into()),
    };
    let transport =
        TokioChildProcess::new(tokio::process::Command::new(program).configure(|command| {
            command.args(server_arguments);
        }))?;
    let client = ().serve(transport).await?;
    let first = client.call_tool(call(first_stimulus, response_mode)?);
    let second = client.call_tool(call(second_stimulus, response_mode)?);
    let (first, second) = tokio::join!(first, second);
    let first = first?;
    let second = second?;
    let first_value = structured(&first)?;
    let second_value = structured(&second)?;
    println!(
        "{}",
        serde_json::to_string(&json!([first_value, second_value]))?
    );
    let statuses = [first_value, second_value];
    let selected = statuses
        .iter()
        .filter(|value| value.get("status").and_then(Value::as_str) == Some("route_selected"))
        .count();
    let busy = statuses
        .iter()
        .filter(|value| {
            value.pointer("/fault/code").and_then(Value::as_str) == Some("runtime_busy")
        })
        .count();
    if response_mode == Some("frame") {
        let selected_value = statuses
            .iter()
            .find(|value| value.get("status").and_then(Value::as_str) == Some("route_selected"))
            .ok_or("frame concurrency result omitted selection")?;
        let busy_value = statuses
            .iter()
            .find(|value| {
                value.pointer("/fault/code").and_then(Value::as_str) == Some("runtime_busy")
            })
            .ok_or("frame concurrency result omitted busy fault")?;
        if selected_value.get("profile").and_then(Value::as_str) != Some(FRAME_RESULT_PROFILE)
            || selected_value.get("runtime").is_some()
            || selected_value.get("verification").is_some()
            || selected_value.get("attention_frame").is_none()
            || busy_value.get("attention_frame").is_some()
        {
            return Err("compact concurrency result crossed its typed boundary".into());
        }
    }
    client.cancel().await?;
    if selected != 1 || busy != 1 {
        return Err(format!(
            "expected one selected and one busy result; observed {selected} and {busy}"
        )
        .into());
    }
    Ok(())
}

fn call(
    stimulus: &str,
    response_mode: Option<&str>,
) -> Result<CallToolRequestParams, Box<dyn std::error::Error>> {
    let mut arguments = json!({ "stimulus": stimulus })
        .as_object()
        .ok_or("tool arguments must be an object")?
        .clone();
    if let Some(response_mode) = response_mode {
        arguments.insert("response_mode".to_owned(), json!(response_mode));
    }
    Ok(CallToolRequestParams::new(TOOL_NAME).with_arguments(arguments))
}

fn structured(result: &CallToolResult) -> Result<&Value, Box<dyn std::error::Error>> {
    result
        .structured_content
        .as_ref()
        .ok_or_else(|| "tool result omitted structuredContent".into())
}
