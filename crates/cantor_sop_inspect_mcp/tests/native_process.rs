mod support;

use cantor_sop_inspect_mcp::{
    MAX_INPUT_FRAME_BYTES, MAX_OUTPUT_FRAME_BYTES, MAX_RESERVED_OUTPUT_BYTES, PUBLIC_HOST_FAULT,
    SESSION_SECONDS, TOOL_NAME,
};
use futures_util::StreamExt;
use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    service::{RoleClient, RxJsonRpcMessage},
    transport::async_rw::JsonRpcMessageCodec,
};
use serde_json::json;
use std::{io, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    time::{Instant, timeout},
};
use tokio_util::codec::FramedRead;

const EXCHANGE: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(1);
fn spawn(arguments: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_cantor-sop-inspect-mcp"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}
async fn capture<R: AsyncRead + Unpin>(reader: R, maximum: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take((maximum + 1) as u64)
        .read_to_end(&mut output)
        .await?;
    if output.len() > maximum {
        return Err(io::Error::other("capture bound"));
    }
    Ok(output)
}
async fn cleanup(child: &mut Child) {
    let _ = timeout(CLEANUP, child.kill()).await;
    let _ = timeout(CLEANUP, child.wait()).await;
}

#[tokio::test]
async fn two_fresh_native_sdk_sessions_replay_all_eight_without_custody_carry() {
    for _ in 0..2 {
        let mut child = spawn(&[]);
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let error = child.stderr.take().unwrap();
        let result = timeout(EXCHANGE, async {
            tokio::try_join!(
                async {
                    // Known scoped child plus aggregate capture bound; the
                    // official SDK owns client dispatch, not a custom parser.
                    let mut client =
                        ().serve((output.take((MAX_RESERVED_OUTPUT_BYTES + 1) as u64), input))
                            .await
                            .map_err(io::Error::other)?;
                    assert_eq!(
                        client
                            .list_tools(Default::default())
                            .await
                            .unwrap()
                            .tools
                            .len(),
                        1
                    );
                    let error = client
                        .call_tool(CallToolRequestParams::new("unknown"))
                        .await
                        .unwrap_err();
                    assert!(matches!(error,rmcp::service::ServiceError::McpError(data)
                        if data.code == rmcp::model::ErrorCode::METHOD_NOT_FOUND));
                    for fixture in support::fixtures() {
                        let result = client
                            .call_tool(
                                CallToolRequestParams::new(TOOL_NAME)
                                    .with_arguments(support::arguments(&fixture.request)),
                            )
                            .await
                            .map_err(io::Error::other)?;
                        support::check_fixture(
                            &fixture,
                            &support::reply(result.structured_content.unwrap()),
                        );
                    }
                    client.close().await.map_err(io::Error::other)?;
                    drop(client);
                    Ok::<_, io::Error>(())
                },
                capture(error, 128),
                child.wait()
            )
        })
        .await;
        match result {
            Ok(Ok(((), stderr, status))) => {
                assert_eq!(status.code(), Some(0));
                assert!(stderr.is_empty());
            }
            failure => {
                cleanup(&mut child).await;
                panic!("bounded native SDK replay failed: {failure:?}");
            }
        }
    }
}

async fn refuse_input(input: Option<Vec<u8>>, arguments: &[&str], close_output: bool) {
    let mut child = spawn(arguments);
    let mut writer = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    let error = child.stderr.take().unwrap();
    let result = timeout(EXCHANGE, async {
        tokio::try_join!(
            async {
                if let Some(input) = input {
                    let _ = writer.write_all(&input).await;
                }
                drop(writer);
                Ok::<_, io::Error>(())
            },
            async {
                if close_output {
                    drop(output);
                    Ok(Vec::new())
                } else {
                    capture(output, MAX_OUTPUT_FRAME_BYTES).await
                }
            },
            capture(error, 128),
            child.wait()
        )
    })
    .await;
    match result {
        Ok(Ok(((), stdout, stderr, status))) => {
            assert_eq!(status.code(), Some(2));
            assert!(stdout.is_empty());
            assert_eq!(stderr, PUBLIC_HOST_FAULT);
        }
        failure => {
            cleanup(&mut child).await;
            panic!("bounded native refusal failed: {failure:?}");
        }
    }
}
#[tokio::test]
async fn cli_extra_argument_refuses_without_echoing() {
    refuse_input(None, &["secret-argument"], false).await;
}
#[tokio::test]
async fn malformed_and_oversized_frame_are_fatal_fixed_faults() {
    refuse_input(None, &[], false).await;
    refuse_input(Some(vec![0xff, b'\n']), &[], false).await;
    refuse_input(Some(b"private-invalid\n".to_vec()), &[], false).await;
    refuse_input(Some(vec![b'x'; MAX_INPUT_FRAME_BYTES + 1]), &[], false).await;
}
fn initialize() -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cantor-bounded-native-fixture","version":"0.1"}}})).unwrap();
    bytes.push(b'\n');
    bytes
}
#[tokio::test]
async fn closed_stdout_refuses_on_handshake_output() {
    refuse_input(Some(initialize()), &[], true).await;
}
#[tokio::test]
async fn capture_exact_plus_one_refuses() {
    assert_eq!(capture(&b"12345678"[..], 8).await.unwrap(), b"12345678");
    assert!(capture(&b"123456789more"[..], 8).await.is_err());
}

#[tokio::test]
async fn real_native_withheld_stdin_and_unread_stdout_exit_at_session_deadline() {
    let mut child = spawn(&[]);
    let mut input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    let error = child.stderr.take().unwrap();
    let started = Instant::now();
    let result = timeout(Duration::from_secs(65),async {
        // Bound setup independently so a bad handshake cannot masquerade as
        // the intentionally sixty-second unread-output adversary.
        let mut held_output = timeout(EXCHANGE,async {
            input.write_all(&initialize()).await?;
            let mut reader = FramedRead::new(output.take((MAX_RESERVED_OUTPUT_BYTES+1) as u64),JsonRpcMessageCodec::<RxJsonRpcMessage<RoleClient>>::new_with_max_length(MAX_OUTPUT_FRAME_BYTES));
            reader.next().await.ok_or_else(||io::Error::other("missing init response"))?.map_err(io::Error::other)?;
            input.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await?;
            // No more stdout reads. Thirty queued responses exceed ordinary
            // anonymous pipe capacity while input stays open. Total decoded
            // messages is exactly32 including the handshake pair.
            let request = support::fixtures().remove(0).request;
            for id in 2..32 {
                let mut bytes = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":TOOL_NAME,"arguments":support::arguments(&request)}})).unwrap();
                bytes.push(b'\n'); input.write_all(&bytes).await?;
            }
            Ok::<_,io::Error>(reader)
        }).await.map_err(io::Error::other)??;
        let (status,stderr) = tokio::try_join!(child.wait(),capture(error,128))?;
        // Retain both taken pipes across Child::wait: it otherwise closes stdin
        // and would invalidate this adversary. No post-exit output drain needed.
        let _ = &mut held_output;
        let _ = &input;
        Ok::<_,io::Error>((status,stderr))
    }).await;
    match result {
        Ok(Ok((status, stderr))) => {
            assert_eq!(status.code(), Some(2));
            assert_eq!(stderr, PUBLIC_HOST_FAULT);
            assert!(started.elapsed() >= Duration::from_secs(SESSION_SECONDS - 1));
            assert!(started.elapsed() < Duration::from_secs(65));
        }
        failure => {
            cleanup(&mut child).await;
            panic!("native deadline did not terminate process: {failure:?}");
        }
    }
}
