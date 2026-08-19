use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use cantor_compact_reflection_loop::{
    FINAL_STATEMENT, RunReport, TerminalObservation, experimental_fixture_context_json,
    inspect_report, verify_report,
};
use serde_json::{Value, json};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_cantor-compact-reflection-loop")
}

fn unique_path(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("cantor-{label}-{}-{nonce}", std::process::id()))
}

#[test]
fn executable_completes_the_full_loopback_model_tool_model_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock provider");
    let address = listener.local_addr().expect("address");
    let server = thread::spawn(move || serve_campaign(listener));

    let context_path = unique_path("loopback-context");
    let report_path = unique_path("loopback-report");
    fs::write(
        &context_path,
        experimental_fixture_context_json().expect("fixture context"),
    )
    .expect("write context");
    let output = Command::new(binary())
        .args([
            "--context",
            context_path.to_str().expect("context path"),
            "--prompt",
            "Run the exact bound procedure and reflect over its terminal identity.",
            "--base-url",
            &format!("http://{address}/v1"),
            "--model",
            "fixture-tool-model",
            "--maximum-steps",
            "64",
            "--output",
            report_path.to_str().expect("report path"),
            "--timeout-seconds",
            "10",
        ])
        .output()
        .expect("run host");
    server.join().expect("mock provider thread");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report_bytes = fs::read(&report_path).expect("report bytes");
    let report: Value = serde_json::from_slice(&report_bytes).expect("report JSON");
    assert_eq!(report["status"], "passed");
    assert_eq!(report["model"], "fixture-tool-model");
    assert_eq!(report["private_reasoning_recorded"], false);
    assert_eq!(
        report.pointer("/final_output/outcome_digest"),
        report.pointer("/terminal_observation/outcome_digest")
    );
    assert!(
        report
            .pointer("/first_response/reasoning_content")
            .is_none()
    );
    assert!(report.pointer("/reflection_response/thinking").is_none());

    let typed: RunReport = serde_json::from_slice(&report_bytes).expect("typed report");
    assert_eq!(verify_report(&typed).expect("verify").status, "verified");
    assert_eq!(inspect_report(&typed).expect("inspect").status, "verified");
    for command in ["verify", "inspect"] {
        let replay = Command::new(binary())
            .args([
                command,
                "--report",
                report_path.to_str().expect("report path"),
            ])
            .output()
            .expect("run replay");
        assert!(
            replay.status.success(),
            "{command} stderr={}",
            String::from_utf8_lossy(&replay.stderr)
        );
    }

    let mut changed = typed.clone();
    changed.profile = "wrong".to_owned();
    assert!(verify_report(&changed).is_err());
    let mut changed = typed.clone();
    changed.first_request["model"] = json!("other-model");
    assert!(verify_report(&changed).is_err());
    let mut changed = typed.clone();
    changed.terminal_observation.outcome_digest.value = "0".repeat(64);
    assert!(verify_report(&changed).is_err());
    let mut changed = typed.clone();
    changed.final_output.outcome_digest.value = "0".repeat(64);
    assert!(verify_report(&changed).is_err());
    let mut changed = typed.clone();
    changed.first_response["reasoning_content"] = json!("private");
    assert!(verify_report(&changed).is_err());
    let mut changed = typed;
    changed.nonclaims.push("expanded".to_owned());
    assert!(verify_report(&changed).is_err());

    fs::remove_file(context_path).expect("remove context");
    fs::remove_file(report_path).expect("remove report");
}

fn serve_campaign(listener: TcpListener) {
    for index in 0..4 {
        let (mut stream, _) = listener.accept().expect("accept");
        let request = read_request(&mut stream);
        let first_line = request.lines().next().expect("request line");
        let response = match index {
            0 => {
                assert_eq!(first_line, "GET / HTTP/1.1");
                json!({"status": "ok"})
            }
            1 => {
                assert_eq!(first_line, "GET /v1/models HTTP/1.1");
                json!({"data": [{"id": "fixture-tool-model"}, {"id": "unused-model"}]})
            }
            2 => {
                assert_eq!(first_line, "POST /v1/chat/completions HTTP/1.1");
                let body = request_body(&request);
                assert_eq!(body["model"], "fixture-tool-model");
                assert_eq!(body["tool_choice"], "required");
                json!({
                    "choices": [{
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "reasoning_content": "must not persist",
                            "tool_calls": [{
                                "id": "call-loopback-1",
                                "type": "function",
                                "function": {
                                    "name": "advance_attention_procedure",
                                    "arguments": "{\"maximum_steps\":64}"
                                }
                            }]
                        }
                    }]
                })
            }
            3 => {
                assert_eq!(first_line, "POST /v1/chat/completions HTTP/1.1");
                let body = request_body(&request);
                assert_eq!(body["tool_choice"], "none");
                let encoded = body
                    .pointer("/messages/3/content")
                    .and_then(Value::as_str)
                    .expect("tool observation");
                let observation: TerminalObservation =
                    serde_json::from_str(encoded).expect("typed observation");
                let final_output = json!({
                    "observed_status": observation.observed_status,
                    "session_id": observation.handle.session_id,
                    "outcome_digest": observation.outcome_digest,
                    "statement": FINAL_STATEMENT
                });
                json!({
                    "thinking": "must not persist",
                    "choices": [{
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": serde_json::to_string(&final_output).unwrap()
                        }
                    }]
                })
            }
            _ => unreachable!(),
        };
        write_json_response(&mut stream, &response);
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end;
    loop {
        let count = stream.read(&mut buffer).expect("read");
        assert!(count > 0, "request closed before headers");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = position + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let count = stream.read(&mut buffer).expect("read body");
        assert!(count > 0, "request closed before body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8(bytes[..header_end + content_length].to_vec()).expect("request UTF-8")
}

fn request_body(request: &str) -> Value {
    let (_, body) = request.split_once("\r\n\r\n").expect("request body");
    serde_json::from_str(body).expect("request JSON")
}

fn write_json_response(stream: &mut TcpStream, value: &Value) {
    let body = serde_json::to_vec(value).expect("response JSON");
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("headers");
    stream.write_all(&body).expect("body");
    stream.flush().expect("flush");
}
