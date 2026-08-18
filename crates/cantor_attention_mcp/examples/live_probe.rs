use std::env;

use cantor_attention_mcp::TOOL_NAME;
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
        .ok_or("usage: live_probe <server-program> [server-args...] --stimulus <text>")?;
    if separator == 0 || separator + 2 != arguments.len() {
        return Err("usage: live_probe <server-program> [server-args...] --stimulus <text>".into());
    }
    let program = &arguments[0];
    let server_arguments = &arguments[1..separator];
    let stimulus = &arguments[separator + 1];
    let transport =
        TokioChildProcess::new(tokio::process::Command::new(program).configure(|command| {
            command.args(server_arguments);
        }))?;
    let client = ().serve(transport).await?;
    let tools = client.list_all_tools().await?;
    if tools.len() != 1 || tools[0].name != TOOL_NAME {
        return Err("server did not publish the exact route_attention surface".into());
    }
    let result = client
        .call_tool(
            CallToolRequestParams::new(TOOL_NAME).with_arguments(
                json!({ "stimulus": stimulus })
                    .as_object()
                    .ok_or("tool arguments must be an object")?
                    .clone(),
            ),
        )
        .await?;
    println!(
        "{}",
        serde_json::to_string(
            result
                .structured_content
                .as_ref()
                .ok_or("tool result omitted structuredContent")?
        )?
    );
    let is_error = result.is_error == Some(true);
    client.cancel().await?;
    if is_error {
        std::process::exit(4);
    }
    Ok(())
}
