use std::env;

use cantor_attention_mcp::TOOL_NAME;
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
        .ok_or("usage: live_concurrency_probe <server-program> [server-args...] --first <text> --second <text>")?;
    if first_marker == 0
        || arguments.get(first_marker + 2).map(String::as_str) != Some("--second")
        || first_marker + 4 != arguments.len()
    {
        return Err("usage: live_concurrency_probe <server-program> [server-args...] --first <text> --second <text>".into());
    }
    let program = &arguments[0];
    let server_arguments = &arguments[1..first_marker];
    let first_stimulus = &arguments[first_marker + 1];
    let second_stimulus = &arguments[first_marker + 3];
    let transport =
        TokioChildProcess::new(tokio::process::Command::new(program).configure(|command| {
            command.args(server_arguments);
        }))?;
    let client = ().serve(transport).await?;
    let first = client.call_tool(call(first_stimulus)?);
    let second = client.call_tool(call(second_stimulus)?);
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
    client.cancel().await?;
    if selected != 1 || busy != 1 {
        return Err(format!(
            "expected one selected and one busy result; observed {selected} and {busy}"
        )
        .into());
    }
    Ok(())
}

fn call(stimulus: &str) -> Result<CallToolRequestParams, Box<dyn std::error::Error>> {
    Ok(CallToolRequestParams::new(TOOL_NAME).with_arguments(
        json!({ "stimulus": stimulus })
            .as_object()
            .ok_or("tool arguments must be an object")?
            .clone(),
    ))
}

fn structured(result: &CallToolResult) -> Result<&Value, Box<dyn std::error::Error>> {
    result
        .structured_content
        .as_ref()
        .ok_or_else(|| "tool result omitted structuredContent".into())
}
