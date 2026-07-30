mod common;

use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    process::Command,
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

use cantor_core::{PreparedRuntime, execute_protocol_request};
use cantor_service::{
    BoundServer, SERVICE_PROTOCOL_VERSION, SecretToken, ServiceDisposition, ServiceOperation,
    ServiceRequest, ServiceResponse, ServiceResult, ServiceRuntime, load_generation,
    load_service_config,
};
use common::{TOKEN, TestWorkspace, id, protocol_fixture, write_json};

#[test]
fn strict_artifacts_preflight_and_restart_reconstruct_exact_binding() {
    let (workspace, _request) = TestWorkspace::new(120, 1);
    let config = load_service_config(&workspace.config_path).expect("config must validate");
    let token = SecretToken::from_file(&config.auth_token_path).expect("token must validate");
    assert!(token.matches(TOKEN));
    assert!(token.matches(&TOKEN.to_ascii_uppercase()));
    assert!(!token.matches("bad"));
    assert_eq!(format!("{token:?}"), "SecretToken([REDACTED])");

    let first = load_generation(&config).expect("generation must load");
    let second = load_generation(&config).expect("generation must reload");
    assert_eq!(first.binding(), second.binding());

    let mut config_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&workspace.config_path).expect("config must read"))
            .expect("config must decode");
    config_value["unknown"] = serde_json::json!(true);
    write_json(&workspace.config_path, &config_value);
    let fault = load_service_config(&workspace.config_path).expect_err("unknown field must fail");
    assert_eq!(fault.code, "invalid_service_config");
    assert!(!fault.to_string().contains(TOKEN));
}

#[test]
fn startup_rejects_remote_bind_digest_tamper_bad_token_and_path_escape() {
    let (workspace, _request) = TestWorkspace::new(120, 1);
    let original_config: serde_json::Value =
        serde_json::from_slice(&fs::read(&workspace.config_path).expect("config must read"))
            .expect("config must decode");

    let mut remote = original_config.clone();
    remote["listen_address"] = serde_json::json!("0.0.0.0:9999");
    write_json(&workspace.config_path, &remote);
    assert_eq!(
        load_service_config(&workspace.config_path)
            .expect_err("remote bind must fail")
            .code,
        "non_loopback_address"
    );

    let mut tiny_frame = original_config.clone();
    tiny_frame["max_frame_bytes"] = serde_json::json!(1);
    write_json(&workspace.config_path, &tiny_frame);
    assert_eq!(
        load_service_config(&workspace.config_path)
            .expect_err("unrepresentable frame limit must fail")
            .code,
        "invalid_resource_limit"
    );

    write_json(&workspace.config_path, &original_config);
    fs::write(&workspace.token_path, "short\n").expect("bad token must write");
    let config = load_service_config(&workspace.config_path).expect("config must validate");
    assert_eq!(
        SecretToken::from_file(&config.auth_token_path)
            .expect_err("bad token must fail")
            .code,
        "invalid_auth_token"
    );

    fs::write(&workspace.token_path, format!("{TOKEN}\n")).expect("token must restore");
    let mut activation: serde_json::Value = serde_json::from_slice(
        &fs::read(&workspace.activation_path).expect("activation must read"),
    )
    .expect("activation must decode");
    let mut unknown_activation = activation.clone();
    unknown_activation["unknown"] = serde_json::json!(true);
    write_json(&workspace.activation_path, &unknown_activation);
    assert_eq!(
        load_generation(&config)
            .expect_err("unknown activation field must fail")
            .code,
        "invalid_activation_descriptor"
    );

    activation["environment_file_sha256"] = serde_json::json!("0".repeat(64));
    write_json(&workspace.activation_path, &activation);
    assert_eq!(
        load_generation(&config)
            .expect_err("digest tamper must fail")
            .code,
        "environment_file_digest_mismatch"
    );

    let outside = workspace
        .root
        .parent()
        .expect("temp parent exists")
        .join(format!("outside-{}.json", std::process::id()));
    fs::copy(&workspace.environment_path, &outside).expect("outside environment must copy");
    activation["environment_path"] = serde_json::json!(outside);
    let outside_bytes = fs::read(&outside).expect("outside environment must read");
    activation["environment_file_sha256"] =
        serde_json::json!(cantor_core::sha256_bytes(&outside_bytes).value);
    write_json(&workspace.activation_path, &activation);
    let fault = load_generation(&config).expect_err("path escape must fail");
    assert_eq!(fault.code, "environment_path_escape");
    let _ = fs::remove_file(outside);
}

#[test]
fn runtime_execute_is_exact_and_refresh_is_monotonic_fail_safe() {
    let (workspace, old_request) = TestWorkspace::new(120, 1);
    let (old_environment, _) = protocol_fixture(120);
    let direct_old = execute_protocol_request(&old_environment, old_request.clone());
    let config = load_service_config(&workspace.config_path).expect("config must validate");
    let token = SecretToken::from_file(&config.auth_token_path).expect("token must validate");
    let loaded = load_generation(&config).expect("generation must load");
    let old_binding = loaded.binding();
    let runtime = ServiceRuntime::new(config, token, loaded);

    let execute = runtime.dispatch(service_request(
        "request:service_execute",
        ServiceOperation::Execute {
            request: Box::new(old_request.clone()),
        },
    ));
    assert_eq!(execute.disposition, ServiceDisposition::Success);
    let ServiceResult::Protocol { response } = execute.result.expect("result is required") else {
        panic!("protocol result is required");
    };
    assert_eq!(*response, direct_old);
    assert_eq!(execute.active_binding, Some(old_binding.clone()));

    let status = runtime.dispatch(service_request(
        "request:service_status",
        ServiceOperation::Status,
    ));
    let ServiceResult::Status { status } = status.result.expect("status result is required") else {
        panic!("status result is required");
    };
    assert_eq!(status.active_binding, old_binding);
    assert_eq!(status.runtime_metrics.executions, 1);

    let new_request = workspace.publish(121, 2);
    let refresh = runtime.dispatch(service_request(
        "request:service_refresh",
        ServiceOperation::Refresh {
            expected_generation_id: old_binding.generation_id.clone(),
            expected_activation_sequence: 1,
        },
    ));
    assert_eq!(refresh.disposition, ServiceDisposition::Success);
    let new_binding = refresh.active_binding.expect("new binding is required");
    assert_eq!(new_binding.activation_sequence, 2);
    assert_ne!(new_binding.generation_id, old_binding.generation_id);

    let stale = runtime.dispatch(service_request(
        "request:service_stale",
        ServiceOperation::Refresh {
            expected_generation_id: old_binding.generation_id,
            expected_activation_sequence: 1,
        },
    ));
    assert_eq!(stale.disposition, ServiceDisposition::Fault);
    assert_eq!(stale.faults[0].code, "stale_generation_expectation");
    assert_eq!(stale.active_binding, Some(new_binding.clone()));

    let stale_sequence = runtime.dispatch(service_request(
        "request:service_stale_sequence",
        ServiceOperation::Refresh {
            expected_generation_id: new_binding.generation_id.clone(),
            expected_activation_sequence: 1,
        },
    ));
    assert_eq!(stale_sequence.disposition, ServiceDisposition::Fault);
    assert_eq!(
        stale_sequence.faults[0].code,
        "stale_activation_expectation"
    );
    assert_eq!(stale_sequence.active_binding, Some(new_binding.clone()));

    workspace.publish(121, 3);
    let unchanged = runtime.dispatch(service_request(
        "request:service_unchanged",
        ServiceOperation::Refresh {
            expected_generation_id: new_binding.generation_id.clone(),
            expected_activation_sequence: 2,
        },
    ));
    assert_eq!(unchanged.disposition, ServiceDisposition::Fault);
    assert_eq!(unchanged.faults[0].code, "unchanged_runtime_generation");
    assert_eq!(unchanged.active_binding, Some(new_binding.clone()));

    let mut activation: serde_json::Value = serde_json::from_slice(
        &fs::read(&workspace.activation_path).expect("activation must read"),
    )
    .expect("activation must decode");
    activation["sequence"] = serde_json::json!(4);
    activation["environment_file_sha256"] = serde_json::json!("f".repeat(64));
    write_json(&workspace.activation_path, &activation);
    let invalid_candidate = runtime.dispatch(service_request(
        "request:service_invalid_candidate",
        ServiceOperation::Refresh {
            expected_generation_id: new_binding.generation_id.clone(),
            expected_activation_sequence: 2,
        },
    ));
    assert_eq!(invalid_candidate.disposition, ServiceDisposition::Fault);
    assert_eq!(
        invalid_candidate.faults[0].code,
        "environment_file_digest_mismatch"
    );
    assert_eq!(invalid_candidate.active_binding, Some(new_binding.clone()));

    let (new_environment, _) = protocol_fixture(121);
    let expected_new = PreparedRuntime::new(new_environment)
        .expect("new runtime must prepare")
        .execute(new_request.clone());
    let execute_new = runtime.dispatch(service_request(
        "request:service_execute_new",
        ServiceOperation::Execute {
            request: Box::new(new_request),
        },
    ));
    let ServiceResult::Protocol { response } =
        execute_new.result.expect("protocol result is required")
    else {
        panic!("protocol result is required");
    };
    assert_eq!(*response, expected_new);
}

#[test]
fn concurrent_readers_observe_only_complete_old_or_new_generations() {
    let (workspace, old_request) = TestWorkspace::new(120, 1);
    let (old_environment, _) = protocol_fixture(120);
    let (new_environment, _) = protocol_fixture(121);
    let old_oracle = PreparedRuntime::new(old_environment)
        .expect("old runtime must prepare")
        .execute(old_request.clone());
    let new_oracle = PreparedRuntime::new(new_environment)
        .expect("new runtime must prepare")
        .execute(old_request.clone());
    assert_ne!(old_oracle, new_oracle);

    let config = load_service_config(&workspace.config_path).expect("config must validate");
    let token = SecretToken::from_file(&config.auth_token_path).expect("token must validate");
    let loaded = load_generation(&config).expect("generation must load");
    let old_binding = loaded.binding();
    let runtime = Arc::new(ServiceRuntime::new(config, token, loaded));
    workspace.publish(121, 2);

    let readers = 12;
    let barrier = Arc::new(Barrier::new(readers + 1));
    let mut handles = Vec::new();
    for worker in 0..readers {
        let runtime = Arc::clone(&runtime);
        let request = old_request.clone();
        let barrier = Arc::clone(&barrier);
        let old_oracle = old_oracle.clone();
        let new_oracle = new_oracle.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            for iteration in 0..200 {
                let response = runtime.dispatch(service_request(
                    &format!("request:reader_{worker}_{iteration}"),
                    ServiceOperation::Execute {
                        request: Box::new(request.clone()),
                    },
                ));
                let ServiceResult::Protocol { response } =
                    response.result.expect("reader result is required")
                else {
                    panic!("reader protocol result is required");
                };
                assert!(*response == old_oracle || *response == new_oracle);
            }
        }));
    }
    barrier.wait();
    let refresh = runtime.dispatch(service_request(
        "request:concurrent_refresh",
        ServiceOperation::Refresh {
            expected_generation_id: old_binding.generation_id,
            expected_activation_sequence: 1,
        },
    ));
    assert_eq!(refresh.disposition, ServiceDisposition::Success);
    for handle in handles {
        handle.join().expect("reader must complete");
    }
}

#[test]
fn live_loopback_transport_authenticates_bounds_and_shuts_down_exactly() {
    let (workspace, request) = TestWorkspace::new(120, 1);
    let server = BoundServer::bind(&workspace.config_path).expect("server must bind");
    let address = server.local_addr().expect("bound address is required");
    let binding = server
        .runtime()
        .active_binding()
        .expect("active binding is required");
    let handle = thread::spawn(move || server.serve().expect("server must serve"));

    let status = send_raw(
        address,
        &service_request("request:live_status", ServiceOperation::Status),
    );
    assert_eq!(status.disposition, ServiceDisposition::Success);

    let execute = send_raw(
        address,
        &service_request(
            "request:live_execute",
            ServiceOperation::Execute {
                request: Box::new(request.clone()),
            },
        ),
    );
    let ServiceResult::Protocol { response } = execute.result.expect("result is required") else {
        panic!("protocol result is required");
    };
    let (environment, _) = protocol_fixture(120);
    assert_eq!(*response, execute_protocol_request(&environment, request));

    let invalid_auth = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION.to_owned(),
        request_id: id("request:bad_auth"),
        auth_token: "f".repeat(64),
        operation: ServiceOperation::Status,
    };
    let auth_response = send_raw(address, &invalid_auth);
    assert_eq!(auth_response.disposition, ServiceDisposition::Fault);
    assert_eq!(auth_response.faults[0].code, "authentication_failed");
    assert_eq!(auth_response.active_binding, None);
    assert!(
        !serde_json::to_string(&auth_response)
            .expect("response must encode")
            .contains(TOKEN)
    );

    let shutdown = send_raw(
        address,
        &service_request(
            "request:live_shutdown",
            ServiceOperation::Shutdown {
                expected_generation_id: binding.generation_id,
            },
        ),
    );
    assert_eq!(shutdown.disposition, ServiceDisposition::Success);
    handle.join().expect("server thread must finish");
}

#[test]
fn connection_budget_rejects_excess_work_and_recovers_capacity() {
    let (workspace, _request) = TestWorkspace::new(120, 1);
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&workspace.config_path).expect("config must read"))
            .expect("config must decode");
    config["max_connections"] = serde_json::json!(1);
    write_json(&workspace.config_path, &config);

    let server = BoundServer::bind(&workspace.config_path).expect("server must bind");
    let address = server.local_addr().expect("bound address is required");
    let binding = server
        .runtime()
        .active_binding()
        .expect("active binding is required");
    let handle = thread::spawn(move || server.serve().expect("server must serve"));

    let blocker = TcpStream::connect(address).expect("blocking client must connect");
    let rejected = send_raw(
        address,
        &service_request("request:over_capacity", ServiceOperation::Status),
    );
    assert_eq!(rejected.disposition, ServiceDisposition::Fault);
    assert_eq!(rejected.faults[0].code, "connection_limit_exceeded");
    assert_eq!(rejected.active_binding, None);
    drop(blocker);

    let status = (0..50)
        .find_map(|attempt| {
            if attempt > 0 {
                thread::sleep(Duration::from_millis(10));
            }
            let response = send_raw(
                address,
                &service_request("request:capacity_recovered", ServiceOperation::Status),
            );
            (response.disposition == ServiceDisposition::Success).then_some(response)
        })
        .expect("capacity must recover after the blocking connection closes");
    let ServiceResult::Status { status } = status.result.expect("status result is required") else {
        panic!("status result is required");
    };
    assert!(status.rejected_connections >= 1);
    assert_eq!(status.worker_panics, 0);

    let shutdown = send_raw(
        address,
        &service_request(
            "request:capacity_shutdown",
            ServiceOperation::Shutdown {
                expected_generation_id: binding.generation_id,
            },
        ),
    );
    assert_eq!(shutdown.disposition, ServiceDisposition::Success);
    handle.join().expect("server thread must finish");
}

#[test]
fn idle_connection_times_out_with_a_bounded_visible_fault() {
    let (workspace, _request) = TestWorkspace::new(120, 1);
    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&workspace.config_path).expect("config must read"))
            .expect("config must decode");
    config["read_timeout_ms"] = serde_json::json!(25);
    write_json(&workspace.config_path, &config);

    let server = BoundServer::bind(&workspace.config_path).expect("server must bind");
    let address = server.local_addr().expect("bound address is required");
    let binding = server
        .runtime()
        .active_binding()
        .expect("active binding is required");
    let handle = thread::spawn(move || server.serve().expect("server must serve"));

    let mut idle = TcpStream::connect(address).expect("idle client must connect");
    idle.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("idle client timeout must set");
    let mut bytes = Vec::new();
    idle.read_to_end(&mut bytes)
        .expect("timeout fault must be readable");
    let response: ServiceResponse =
        serde_json::from_slice(&bytes).expect("timeout fault must decode");
    assert_eq!(response.disposition, ServiceDisposition::Fault);
    assert_eq!(response.faults[0].code, "frame_read_failed");
    assert!(response.faults[0].message.chars().count() <= 512);
    assert_eq!(response.active_binding, None);

    let shutdown = send_raw(
        address,
        &service_request(
            "request:timeout_shutdown",
            ServiceOperation::Shutdown {
                expected_generation_id: binding.generation_id,
            },
        ),
    );
    assert_eq!(shutdown.disposition, ServiceDisposition::Success);
    handle.join().expect("server thread must finish");
}

#[test]
fn strict_wire_faults_and_cantorctl_use_the_live_service_without_semantic_drift() {
    let (workspace, _request) = TestWorkspace::new(120, 1);
    let server = BoundServer::bind(&workspace.config_path).expect("server must bind");
    let address = server.local_addr().expect("bound address is required");
    let binding = server
        .runtime()
        .active_binding()
        .expect("active binding is required");
    let handle = thread::spawn(move || server.serve().expect("server must serve"));

    let mut config: serde_json::Value =
        serde_json::from_slice(&fs::read(&workspace.config_path).expect("config must read"))
            .expect("config must decode");
    config["listen_address"] = serde_json::json!(address.to_string());
    write_json(&workspace.config_path, &config);

    let output = Command::new(env!("CARGO_BIN_EXE_cantorctl"))
        .args([
            "status",
            "--config",
            workspace
                .config_path
                .to_str()
                .expect("test config path is UTF-8"),
            "--request-id",
            "request:cantorctl_status",
        ])
        .output()
        .expect("cantorctl must run");
    assert!(output.status.success(), "{output:?}");
    let response: ServiceResponse =
        serde_json::from_slice(&output.stdout).expect("cantorctl response must decode");
    assert_eq!(response.disposition, ServiceDisposition::Success);
    assert_eq!(response.request_id, id("request:cantorctl_status"));

    let mut unknown = serde_json::to_value(service_request(
        "request:unknown_wire",
        ServiceOperation::Status,
    ))
    .expect("request must encode");
    unknown["unexpected"] = serde_json::json!(true);
    let mut stream = TcpStream::connect(address).expect("wire client must connect");
    let mut bytes = serde_json::to_vec(&unknown).expect("wire request must encode");
    bytes.push(b'\n');
    stream.write_all(&bytes).expect("wire request must write");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("wire response must read");
    let unknown_response: ServiceResponse =
        serde_json::from_slice(&raw).expect("wire response must decode");
    assert_eq!(unknown_response.disposition, ServiceDisposition::Fault);
    assert_eq!(unknown_response.faults[0].code, "invalid_service_request");
    assert_eq!(unknown_response.active_binding, None);

    let empty = send_bytes(address, b"", true);
    assert_eq!(empty.disposition, ServiceDisposition::Fault);
    assert_eq!(empty.faults[0].code, "empty_frame");
    assert_eq!(empty.active_binding, None);

    let mut unsupported = service_request("request:wrong_version", ServiceOperation::Status);
    unsupported.protocol_version = "cantor-service-protocol/999".to_owned();
    let unsupported_response = send_raw(address, &unsupported);
    assert_eq!(
        unsupported_response.faults[0].code,
        "unsupported_service_protocol"
    );
    assert_eq!(unsupported_response.active_binding, Some(binding.clone()));

    unsupported.auth_token = "f".repeat(64);
    let unauthenticated_response = send_raw(address, &unsupported);
    assert_eq!(
        unauthenticated_response.faults[0].code,
        "authentication_failed"
    );
    assert_eq!(unauthenticated_response.active_binding, None);

    let oversized = send_bytes(address, &vec![b'x'; 1024 * 1024 + 1], true);
    assert_eq!(oversized.disposition, ServiceDisposition::Fault);
    assert_eq!(oversized.faults[0].code, "frame_limit_exceeded");
    assert_eq!(oversized.active_binding, None);

    let unterminated = send_bytes(address, br#"{"protocol_version":"incomplete"}"#, false);
    assert_eq!(unterminated.disposition, ServiceDisposition::Fault);
    assert_eq!(unterminated.faults[0].code, "unterminated_frame");
    assert_eq!(unterminated.active_binding, None);

    let shutdown = send_raw(
        address,
        &service_request(
            "request:cantorctl_test_shutdown",
            ServiceOperation::Shutdown {
                expected_generation_id: binding.generation_id,
            },
        ),
    );
    assert_eq!(shutdown.disposition, ServiceDisposition::Success);
    handle.join().expect("server thread must finish");
}

fn service_request(request_id: &str, operation: ServiceOperation) -> ServiceRequest {
    ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION.to_owned(),
        request_id: id(request_id),
        auth_token: TOKEN.to_owned(),
        operation,
    }
}

fn send_raw(address: std::net::SocketAddr, request: &ServiceRequest) -> ServiceResponse {
    let mut stream = TcpStream::connect(address).expect("client must connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout must set");
    let bytes = serde_json::to_vec(request).expect("request must encode");
    stream.write_all(&bytes).expect("request must write");
    stream.write_all(b"\n").expect("request must terminate");
    stream.flush().expect("request must flush");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("response must read");
    serde_json::from_slice(&response).expect("response must decode")
}

fn send_bytes(address: std::net::SocketAddr, bytes: &[u8], terminate: bool) -> ServiceResponse {
    let mut stream = TcpStream::connect(address).expect("wire client must connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout must set");
    stream.write_all(bytes).expect("wire bytes must write");
    if terminate {
        stream.write_all(b"\n").expect("wire frame must terminate");
    } else {
        stream
            .shutdown(Shutdown::Write)
            .expect("client write half must close");
    }
    stream.flush().expect("wire bytes must flush");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("wire response must read");
    serde_json::from_slice(&response).expect("wire response must decode")
}
