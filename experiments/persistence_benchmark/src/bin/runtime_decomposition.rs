#[path = "../fixture.rs"]
mod fixture;

use std::{
    env, fs,
    hint::black_box,
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use cantor_core::{
    AuthorityScope, EmbeddedRuntimeEnvironment, ProtocolOperation, ProtocolOutcome, SemanticFabric,
    admit_package, embedded_environment_digest, execute_protocol_request, execute_query,
};
use serde::Serialize;

use crate::fixture::build_fixture;

#[derive(Debug, Serialize)]
struct RuntimeDecompositionReport {
    report_version: &'static str,
    captured_at_epoch_milliseconds: u128,
    machine: String,
    operating_system: String,
    rustc: String,
    compilation_boundary: &'static str,
    boundary: &'static str,
    scenarios: Vec<Scenario>,
}

#[derive(Debug, Serialize)]
struct Scenario {
    package_count: usize,
    iterations: usize,
    environment_digest_microseconds: Distribution,
    admit_and_build_fabric_microseconds: Distribution,
    prepared_query_microseconds: Distribution,
    full_protocol_microseconds: Distribution,
    prepared_query_equals_protocol_query: bool,
    repeated_protocol_response_equal: bool,
}

#[derive(Debug, Serialize)]
struct Distribution {
    minimum: u128,
    median: u128,
    p95: u128,
    maximum: u128,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: runtime_decomposition <output-report.json>")?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut scenarios = Vec::new();
    for package_count in [1_usize, 32, 256] {
        scenarios.push(profile(package_count)?);
    }
    let report = RuntimeDecompositionReport {
        report_version: "cantor-runtime-decomposition/0.2",
        captured_at_epoch_milliseconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        machine: env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_owned()),
        operating_system: format!("{} {}", env::consts::OS, env::consts::ARCH),
        rustc: command_version("rustc")?,
        compilation_boundary: "unsafe code forbidden; release overflow checks enabled",
        boundary: "warm in-process timing; prepared query excludes environment digest, expected-package comparison, signature admission, and fabric construction",
        scenarios,
    };
    fs::write(output_path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

fn profile(package_count: usize) -> Result<Scenario, Box<dyn std::error::Error>> {
    let (environment, request) = build_fixture(package_count)?;
    let query = match &request.request {
        ProtocolOperation::Query { query } => query.as_ref(),
        ProtocolOperation::Inspect { .. } => return Err("fixture must contain a query".into()),
    };
    let oracle = execute_protocol_request(&environment, request.clone());
    let oracle_query = match &oracle.result {
        ProtocolOutcome::Query(result) => result,
        _ => return Err("fixture protocol execution did not return a query result".into()),
    };
    let prepared_fabric = prepare_fabric(&environment, &request.requested_scope)?;
    let prepared_result = execute_query(&prepared_fabric, query).map_err(query_error)?;
    let prepared_query_equals_protocol_query = prepared_result == *oracle_query;
    if !prepared_query_equals_protocol_query {
        return Err("prepared query differs from protocol query result".into());
    }

    let iterations = match package_count {
        1 => 200,
        32 => 100,
        _ => 30,
    };
    let mut digest_samples = Vec::with_capacity(iterations);
    let mut prepare_samples = Vec::with_capacity(iterations);
    let mut prepared_query_samples = Vec::with_capacity(iterations);
    let mut protocol_samples = Vec::with_capacity(iterations);
    let mut repeated_protocol_response_equal = true;

    for _ in 0..iterations {
        let started = Instant::now();
        let digest = embedded_environment_digest(&environment)?;
        digest_samples.push(started.elapsed().as_micros());
        black_box(digest);

        let started = Instant::now();
        let fabric = prepare_fabric(&environment, &request.requested_scope)?;
        prepare_samples.push(started.elapsed().as_micros());
        black_box(fabric);

        let started = Instant::now();
        let result = execute_query(&prepared_fabric, query).map_err(query_error)?;
        prepared_query_samples.push(started.elapsed().as_micros());
        if result != *oracle_query {
            return Err("prepared query response drifted".into());
        }
        black_box(result);

        let started = Instant::now();
        let response = execute_protocol_request(&environment, request.clone());
        protocol_samples.push(started.elapsed().as_micros());
        repeated_protocol_response_equal &= response == oracle;
        black_box(response);
    }
    if !repeated_protocol_response_equal {
        return Err("protocol response drifted".into());
    }

    Ok(Scenario {
        package_count,
        iterations,
        environment_digest_microseconds: distribution(digest_samples),
        admit_and_build_fabric_microseconds: distribution(prepare_samples),
        prepared_query_microseconds: distribution(prepared_query_samples),
        full_protocol_microseconds: distribution(protocol_samples),
        prepared_query_equals_protocol_query,
        repeated_protocol_response_equal,
    })
}

fn prepare_fabric(
    environment: &EmbeddedRuntimeEnvironment,
    requested_scope: &AuthorityScope,
) -> Result<SemanticFabric, Box<dyn std::error::Error>> {
    let admitted = environment
        .packages
        .iter()
        .map(|package| {
            admit_package(
                package,
                &environment.trust_store,
                requested_scope,
                environment.now_epoch_seconds,
            )
            .map_err(|fault| {
                format!(
                    "package admission failed ({:?}): {}",
                    fault.kind, fault.message
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    SemanticFabric::from_admitted(admitted).map_err(query_error)
}

fn query_error(fault: cantor_core::QueryFault) -> Box<dyn std::error::Error> {
    format!(
        "query fault ({:?}, {}): {}",
        fault.kind, fault.stage, fault.message
    )
    .into()
}

fn distribution(mut samples: Vec<u128>) -> Distribution {
    samples.sort_unstable();
    let p95_index = ((samples.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(samples.len() - 1);
    Distribution {
        minimum: samples[0],
        median: samples[samples.len() / 2],
        p95: samples[p95_index],
        maximum: samples[samples.len() - 1],
    }
}

fn command_version(command: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(command).arg("--version").output()?;
    if !output.status.success() {
        return Err(format!("{command} --version failed").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
