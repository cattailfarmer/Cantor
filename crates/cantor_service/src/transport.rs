use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    artifacts::{SecretToken, load_generation, load_service_config},
    model::{
        SERVICE_PROTOCOL_VERSION, ServiceDisposition, ServiceFault, ServiceRequest,
        ServiceResponse, unavailable_request_id,
    },
    runtime::ServiceRuntime,
};

pub struct BoundServer {
    listener: TcpListener,
    runtime: Arc<ServiceRuntime>,
}

struct ConnectionLease {
    active_connections: Arc<AtomicUsize>,
}

impl ConnectionLease {
    fn acquire(active_connections: Arc<AtomicUsize>) -> Self {
        active_connections.fetch_add(1, Ordering::AcqRel);
        Self { active_connections }
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

impl BoundServer {
    pub fn bind(config_path: &Path) -> Result<Self, ServiceFault> {
        let config = load_service_config(config_path)?;
        let token = SecretToken::from_file(&config.auth_token_path)?;
        let generation = load_generation(&config)?;
        let listener = TcpListener::bind(config.listen_address).map_err(|error| {
            ServiceFault::new(
                "listener_bind_failed",
                "startup",
                format!("cannot bind configured loopback listener: {error}"),
            )
        })?;
        Ok(Self {
            listener,
            runtime: Arc::new(ServiceRuntime::new(config, token, generation)),
        })
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ServiceFault> {
        self.listener.local_addr().map_err(|error| {
            ServiceFault::new(
                "listener_address_failed",
                "startup",
                format!("cannot inspect bound listener: {error}"),
            )
        })
    }

    pub fn runtime(&self) -> &Arc<ServiceRuntime> {
        &self.runtime
    }

    pub fn serve(self) -> Result<(), ServiceFault> {
        let active_connections = Arc::new(AtomicUsize::new(0));
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        let wake_address = self.local_addr()?;
        while !self.runtime.shutdown_requested() {
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    if self.runtime.shutdown_requested() {
                        write_unavailable_fault(
                            stream,
                            self.runtime.config().read_timeout,
                            self.runtime.config().write_timeout,
                            self.runtime.config().max_frame_bytes,
                            ServiceFault::new(
                                "service_shutting_down",
                                "transport",
                                "service is no longer accepting requests",
                            ),
                        );
                        continue;
                    }
                    self.runtime.record_accepted_connection();
                    if active_connections.load(Ordering::Acquire)
                        >= self.runtime.config().max_connections
                    {
                        self.runtime.record_rejected_connection();
                        write_unavailable_fault(
                            stream,
                            self.runtime.config().read_timeout,
                            self.runtime.config().write_timeout,
                            self.runtime.config().max_frame_bytes,
                            ServiceFault::new(
                                "connection_limit_exceeded",
                                "transport",
                                "service connection budget is exhausted",
                            ),
                        );
                        continue;
                    }
                    let runtime = Arc::clone(&self.runtime);
                    let lease = ConnectionLease::acquire(Arc::clone(&active_connections));
                    workers.push(thread::spawn(move || {
                        let _lease = lease;
                        handle_connection(stream, &runtime, wake_address);
                    }));
                    reap_finished_workers(&mut workers, &self.runtime);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    join_workers(workers, &self.runtime);
                    return Err(ServiceFault::new(
                        "listener_accept_failed",
                        "transport",
                        format!("listener failed to accept a connection: {error}"),
                    ));
                }
            }
        }
        join_workers(workers, &self.runtime);
        Ok(())
    }
}

fn join_workers(workers: Vec<JoinHandle<()>>, runtime: &ServiceRuntime) {
    for worker in workers {
        if worker.join().is_err() {
            runtime.record_worker_panic();
        }
    }
}

fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>, runtime: &ServiceRuntime) {
    let mut position = 0;
    while position < workers.len() {
        if workers[position].is_finished() {
            let worker = workers.swap_remove(position);
            if worker.join().is_err() {
                runtime.record_worker_panic();
            }
        } else {
            position += 1;
        }
    }
}

pub fn send_request(
    config_path: &Path,
    operation: crate::model::ServiceOperation,
    request_id: cantor_core::SemanticId,
) -> Result<ServiceResponse, ServiceFault> {
    let config = load_service_config(config_path)?;
    let token = SecretToken::from_file(&config.auth_token_path)?;
    let request = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION.to_owned(),
        request_id: request_id.clone(),
        auth_token: token.expose_for_client(),
        operation,
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| {
        ServiceFault::new(
            "request_encoding_failed",
            "client",
            format!("cannot serialize service request: {error}"),
        )
    })?;
    if request_bytes.len() > config.max_frame_bytes {
        return Err(ServiceFault::new(
            "frame_limit_exceeded",
            "client",
            "serialized service request exceeds configured frame limit",
        ));
    }
    let mut stream = TcpStream::connect(config.listen_address).map_err(|error| {
        ServiceFault::new(
            "service_connect_failed",
            "client",
            format!("cannot connect to configured Cantor service: {error}"),
        )
    })?;
    configure_stream(&stream, config.read_timeout, config.write_timeout)?;
    stream.write_all(&request_bytes).map_err(|error| {
        ServiceFault::new(
            "request_write_failed",
            "client",
            format!("cannot write service request: {error}"),
        )
    })?;
    stream.write_all(b"\n").map_err(|error| {
        ServiceFault::new(
            "request_write_failed",
            "client",
            format!("cannot terminate service request: {error}"),
        )
    })?;
    stream.flush().map_err(|error| {
        ServiceFault::new(
            "request_write_failed",
            "client",
            format!("cannot flush service request: {error}"),
        )
    })?;
    stream.shutdown(Shutdown::Write).map_err(|error| {
        ServiceFault::new(
            "request_write_shutdown_failed",
            "client",
            format!("cannot close the completed service request stream: {error}"),
        )
    })?;
    let bytes = read_frame(&mut stream, config.max_frame_bytes)?;
    let response: ServiceResponse = serde_json::from_slice(&bytes).map_err(|error| {
        ServiceFault::new(
            "invalid_service_response",
            "client",
            format!("service response is not valid strict JSON: {error}"),
        )
    })?;
    if response.protocol_version != SERVICE_PROTOCOL_VERSION {
        return Err(ServiceFault::new(
            "service_protocol_mismatch",
            "client",
            "service response uses an unsupported protocol version",
        ));
    }
    if response.request_id != request_id {
        return Err(ServiceFault::new(
            "service_request_identity_mismatch",
            "client",
            "service response request identity differs from the request",
        ));
    }
    Ok(response)
}

fn handle_connection(
    mut stream: TcpStream,
    runtime: &ServiceRuntime,
    wake_address: std::net::SocketAddr,
) {
    if configure_stream(
        &stream,
        runtime.config().read_timeout,
        runtime.config().write_timeout,
    )
    .is_err()
    {
        return;
    }
    let response = match read_frame(&mut stream, runtime.config().max_frame_bytes) {
        Ok(bytes) => match serde_json::from_slice::<ServiceRequest>(&bytes) {
            Ok(request) => runtime.dispatch(request),
            Err(error) => ServiceResponse::fault(
                unavailable_request_id(),
                None,
                ServiceFault::new(
                    "invalid_service_request",
                    "transport_decode",
                    format!("request is not valid strict service JSON: {error}"),
                ),
            ),
        },
        Err(fault) => ServiceResponse::fault(unavailable_request_id(), None, fault),
    };
    let _ = write_response(&mut stream, &response, runtime.config().max_frame_bytes);
    let _ = stream.shutdown(Shutdown::Both);
    if matches!(
        response.result,
        Some(crate::model::ServiceResult::Shutdown { .. })
    ) {
        let _ = TcpStream::connect(wake_address);
    }
}

fn configure_stream(
    stream: &TcpStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), ServiceFault> {
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|error| {
            ServiceFault::new(
                "stream_configuration_failed",
                "transport",
                format!("cannot configure read timeout: {error}"),
            )
        })?;
    stream
        .set_write_timeout(Some(write_timeout))
        .map_err(|error| {
            ServiceFault::new(
                "stream_configuration_failed",
                "transport",
                format!("cannot configure write timeout: {error}"),
            )
        })
}

fn read_frame(stream: &mut TcpStream, maximum: usize) -> Result<Vec<u8>, ServiceFault> {
    let mut frame = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = stream.read(&mut chunk).map_err(|error| {
            ServiceFault::new(
                "frame_read_failed",
                "transport",
                format!("cannot read service frame: {error}"),
            )
        })?;
        if count == 0 {
            return Err(ServiceFault::new(
                "unterminated_frame",
                "transport",
                "connection closed before the service frame LF terminator",
            ));
        }
        if let Some(position) = chunk[..count].iter().position(|byte| *byte == b'\n') {
            if position + 1 != count {
                return Err(ServiceFault::new(
                    "multiple_frames",
                    "transport",
                    "one connection may contain exactly one service request frame",
                ));
            }
            if frame.len().saturating_add(position) > maximum {
                return Err(frame_limit_fault(maximum));
            }
            frame.extend_from_slice(&chunk[..position]);
            if frame.is_empty() {
                return Err(ServiceFault::new(
                    "empty_frame",
                    "transport",
                    "service request frame is empty",
                ));
            }
            return Ok(frame);
        }
        if frame.len().saturating_add(count) > maximum {
            return Err(frame_limit_fault(maximum));
        }
        frame.extend_from_slice(&chunk[..count]);
    }
}

fn write_response(
    stream: &mut TcpStream,
    response: &ServiceResponse,
    maximum: usize,
) -> Result<(), ServiceFault> {
    let mut bytes = serde_json::to_vec(response).map_err(|error| {
        ServiceFault::new(
            "response_encoding_failed",
            "transport",
            format!("cannot serialize service response: {error}"),
        )
    })?;
    if bytes.len() > maximum {
        let fallback = ServiceResponse::fault(
            response.request_id.clone(),
            response.active_binding.clone(),
            ServiceFault::new(
                "response_limit_exceeded",
                "transport",
                "service response exceeds configured frame limit",
            ),
        );
        bytes = serde_json::to_vec(&fallback).map_err(|error| {
            ServiceFault::new(
                "response_encoding_failed",
                "transport",
                format!("cannot serialize bounded fault response: {error}"),
            )
        })?;
    }
    stream.write_all(&bytes).map_err(|error| {
        ServiceFault::new(
            "response_write_failed",
            "transport",
            format!("cannot write service response: {error}"),
        )
    })?;
    stream.write_all(b"\n").map_err(|error| {
        ServiceFault::new(
            "response_write_failed",
            "transport",
            format!("cannot terminate service response: {error}"),
        )
    })?;
    stream.flush().map_err(|error| {
        ServiceFault::new(
            "response_write_failed",
            "transport",
            format!("cannot flush service response: {error}"),
        )
    })
}

fn write_unavailable_fault(
    mut stream: TcpStream,
    read_timeout: Duration,
    write_timeout: Duration,
    maximum: usize,
    fault: ServiceFault,
) {
    drain_rejected_request(&mut stream, read_timeout, maximum);
    let _ = stream.set_write_timeout(Some(write_timeout));
    let response = ServiceResponse::fault(unavailable_request_id(), None, fault);
    let _ = write_response(&mut stream, &response, maximum);
    let _ = stream.shutdown(Shutdown::Both);
}

fn drain_rejected_request(stream: &mut TcpStream, configured_timeout: Duration, maximum: usize) {
    let drain_timeout = configured_timeout.min(Duration::from_millis(25));
    let _ = stream.set_read_timeout(Some(drain_timeout));
    let mut remaining = maximum.saturating_add(1);
    let mut chunk = [0_u8; 4096];
    while remaining > 0 {
        let capacity = remaining.min(chunk.len());
        match stream.read(&mut chunk[..capacity]) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                remaining = remaining.saturating_sub(count);
                if chunk[..count].contains(&b'\n') {
                    break;
                }
            }
        }
    }
}

fn frame_limit_fault(maximum: usize) -> ServiceFault {
    ServiceFault::new(
        "frame_limit_exceeded",
        "transport",
        format!("service request exceeds the configured {maximum}-byte frame limit"),
    )
}

pub fn response_exit_code(response: &ServiceResponse) -> u8 {
    if response.disposition == ServiceDisposition::Fault {
        return 2;
    }
    match response.result.as_ref() {
        Some(crate::model::ServiceResult::Protocol { response }) => response.exit_class.code(),
        _ => 0,
    }
}
