use std::{
    env, fs,
    hint::black_box,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use cantor_core::{PreparedRuntime, ProtocolRequest, ProtocolResponse, SemanticId};
use cantor_service::{
    BoundServer, SERVICE_PROTOCOL_VERSION, SecretToken, ServiceConfig, ServiceDisposition,
    ServiceOperation, ServiceRequest, ServiceResult, load_generation, load_service_config,
    send_request,
};
use serde::Serialize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1).collect())?;
    let temporary = TemporaryConfiguration::create(&arguments.config)?;
    let startup_started = Instant::now();
    let server = BoundServer::bind(&temporary.path)?;
    let startup_microseconds = elapsed_microseconds(startup_started);
    let address = server.local_addr()?;
    temporary.publish_address(address)?;
    let runtime = Arc::clone(server.runtime());
    let config = load_service_config(&temporary.path)?;
    let token = SecretToken::from_file(&config.auth_token_path)?.expose_for_client();
    let oracle_loaded = load_generation(&config)?;
    let oracle = PreparedRuntime::new(oracle_loaded.runtime.environment().clone())?;
    let request: ProtocolRequest = serde_json::from_slice(&fs::read(&arguments.request)?)?;
    let expected = oracle.execute(request.clone());
    let generation_id = runtime.active_binding()?.generation_id;
    let package_count = oracle.generation().ordered_package_ids.len();
    let environment_bytes = fs::metadata(&oracle_loaded.activation.environment_path)?.len();

    let server_thread = thread::spawn(move || server.serve());
    let mut mismatches = 0_u64;

    let restart_preflight = measure(arguments.iterations, || {
        let loaded = load_generation(&config).expect("measured generation load must succeed");
        black_box(loaded.binding());
    });
    let resident_dispatch = measure(arguments.iterations, || {
        let response = runtime.dispatch(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION.to_owned(),
            request_id: id("request:benchmark_resident"),
            auth_token: token.clone(),
            operation: ServiceOperation::Execute {
                request: Box::new(request.clone()),
            },
        });
        if protocol_response(&response) != Some(&expected) {
            mismatches += 1;
        }
        black_box(response);
    });
    let status_round_trip = measure(arguments.iterations, || {
        let response = send_request(
            &temporary.path,
            ServiceOperation::Status,
            id("request:benchmark_status"),
        )
        .expect("measured status request must succeed");
        if response.disposition != ServiceDisposition::Success
            || response
                .active_binding
                .as_ref()
                .map(|binding| &binding.generation_id)
                != Some(&generation_id)
        {
            mismatches += 1;
        }
        black_box(response);
    });
    let query_round_trip = measure(arguments.iterations, || {
        let response = send_request(
            &temporary.path,
            ServiceOperation::Execute {
                request: Box::new(request.clone()),
            },
            id("request:benchmark_query"),
        )
        .expect("measured query request must succeed");
        if protocol_response(&response) != Some(&expected) {
            mismatches += 1;
        }
        black_box(response);
    });

    let shutdown = send_request(
        &temporary.path,
        ServiceOperation::Shutdown {
            expected_generation_id: generation_id.clone(),
        },
        id("request:benchmark_shutdown"),
    )?;
    if shutdown.disposition != ServiceDisposition::Success {
        mismatches += 1;
    }
    server_thread
        .join()
        .map_err(|_| "service thread panicked")??;

    let report = Report {
        schema: "cantor-resident-service-benchmark/0.1",
        generated_at_epoch_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        iterations: arguments.iterations,
        environment_bytes,
        package_count,
        generation_id: generation_id.value,
        startup_microseconds,
        restart_preflight,
        resident_dispatch,
        status_round_trip,
        query_round_trip,
        correctness_mismatches: mismatches,
    };
    if let Some(parent) = arguments.output.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(&arguments.output, bytes)?;
    println!("{}", arguments.output.display());
    if mismatches == 0 {
        Ok(())
    } else {
        Err(format!("benchmark observed {mismatches} correctness mismatches").into())
    }
}

fn protocol_response(response: &cantor_service::ServiceResponse) -> Option<&ProtocolResponse> {
    match response.result.as_ref()? {
        ServiceResult::Protocol { response } => Some(response),
        _ => None,
    }
}

fn id(value: &str) -> SemanticId {
    SemanticId::new(value).expect("benchmark identities are valid")
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    generated_at_epoch_seconds: u64,
    iterations: usize,
    environment_bytes: u64,
    package_count: usize,
    generation_id: String,
    startup_microseconds: u64,
    restart_preflight: Measurement,
    resident_dispatch: Measurement,
    status_round_trip: Measurement,
    query_round_trip: Measurement,
    correctness_mismatches: u64,
}

#[derive(Serialize)]
struct Measurement {
    samples_microseconds: Vec<u64>,
    minimum_microseconds: u64,
    median_microseconds: u64,
    p95_microseconds: u64,
    maximum_microseconds: u64,
}

fn measure(mut iterations: usize, mut operation: impl FnMut()) -> Measurement {
    let mut samples = Vec::with_capacity(iterations);
    while iterations > 0 {
        let started = Instant::now();
        operation();
        samples.push(elapsed_microseconds(started));
        iterations -= 1;
    }
    let mut ordered = samples.clone();
    ordered.sort_unstable();
    let median_index = ordered.len() / 2;
    let p95_index = (ordered.len() * 95).div_ceil(100).saturating_sub(1);
    Measurement {
        minimum_microseconds: ordered[0],
        median_microseconds: ordered[median_index],
        p95_microseconds: ordered[p95_index],
        maximum_microseconds: *ordered.last().expect("at least one sample is required"),
        samples_microseconds: samples,
    }
}

fn elapsed_microseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

struct Arguments {
    config: PathBuf,
    request: PathBuf,
    iterations: usize,
    output: PathBuf,
}

impl Arguments {
    fn parse(arguments: Vec<String>) -> Result<Self, String> {
        let mut config = None;
        let mut request = None;
        let mut iterations = None;
        let mut output = None;
        if !arguments.len().is_multiple_of(2) {
            return Err("every benchmark flag requires one value".to_owned());
        }
        for pair in arguments.chunks_exact(2) {
            match pair[0].as_str() {
                "--config" if config.is_none() => config = Some(PathBuf::from(&pair[1])),
                "--request" if request.is_none() => request = Some(PathBuf::from(&pair[1])),
                "--iterations" if iterations.is_none() => {
                    iterations = Some(
                        pair[1]
                            .parse::<usize>()
                            .map_err(|error| format!("invalid iterations: {error}"))?,
                    )
                }
                "--output" if output.is_none() => output = Some(PathBuf::from(&pair[1])),
                flag => return Err(format!("unknown or duplicate benchmark flag {flag:?}")),
            }
        }
        let iterations = iterations.ok_or("--iterations is required")?;
        if iterations == 0 || iterations > 10_000 {
            return Err("--iterations must be from 1 through 10000".to_owned());
        }
        Ok(Self {
            config: config.ok_or("--config is required")?,
            request: request.ok_or("--request is required")?,
            iterations,
            output: output.ok_or("--output is required")?,
        })
    }
}

struct TemporaryConfiguration {
    root: PathBuf,
    path: PathBuf,
    config: ServiceConfig,
}

impl TemporaryConfiguration {
    fn create(source: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = fs::read(source)?;
        let mut config: ServiceConfig = serde_json::from_slice(&bytes)?;
        config.listen_address = "127.0.0.1:0".to_owned();
        let root = env::temp_dir().join(format!(
            "cantor-service-benchmark-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&root)?;
        let path = root.join("service.json");
        write_config(&path, &config)?;
        Ok(Self { root, path, config })
    }

    fn publish_address(
        &self,
        address: std::net::SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = self.config.clone();
        config.listen_address = address.to_string();
        write_config(&self.path, &config)
    }
}

impl Drop for TemporaryConfiguration {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_config(path: &Path, config: &ServiceConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(config)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
