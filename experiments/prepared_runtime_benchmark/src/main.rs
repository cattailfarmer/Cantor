#[path = "../../persistence_benchmark/src/fixture.rs"]
mod fixture;

use std::{
    env,
    error::Error,
    hint::black_box,
    time::{Duration, Instant},
};

#[cfg(feature = "dhat-heap")]
use cantor_core::ProtocolResponse;
use cantor_core::{PreparedRuntime, execute_protocol_request};
use serde::Serialize;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Serialize)]
struct DurationSummary {
    samples: usize,
    minimum_us: f64,
    median_us: f64,
    p95_us: f64,
    maximum_us: f64,
}

#[derive(Serialize)]
struct LatencyReport {
    schema: &'static str,
    package_count: usize,
    iterations: usize,
    cold_process_prepare: DurationSummary,
    direct_request: DurationSummary,
    prepared_construct: DurationSummary,
    warm_scope_preparation: DurationSummary,
    cold_runtime_first_request: DurationSummary,
    prepared_scope_replacement: DurationSummary,
    prepared_hit: DurationSummary,
    exact_response_mismatches: usize,
    runtime_metrics_after_hits: cantor_core::PreparedRuntimeMetrics,
}

#[cfg(feature = "dhat-heap")]
#[derive(Serialize)]
struct MemoryReport {
    schema: &'static str,
    mode: String,
    package_count: usize,
    current_bytes: usize,
    current_blocks: usize,
    peak_bytes: usize,
    peak_blocks: usize,
    total_allocated_bytes: u64,
    total_allocated_blocks: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("latency") => {
            let package_count = parse_usize(arguments.get(1), "package_count")?;
            let iterations = parse_usize(arguments.get(2), "iterations")?;
            latency(package_count, iterations, arguments.get(3))
        }
        #[cfg(feature = "dhat-heap")]
        Some("memory") => {
            let mode = arguments.get(1).ok_or("memory mode is required")?;
            let package_count = parse_usize(arguments.get(2), "package_count")?;
            memory(mode, package_count, arguments.get(3))
        }
        #[cfg(not(feature = "dhat-heap"))]
        Some("memory") => Err("memory mode requires --features dhat-heap".into()),
        _ => Err(
            "usage: prepared-runtime-benchmark latency <package_count> <iterations> | memory <baseline|prepared> <package_count>"
                .into(),
        ),
    }
}

fn parse_usize(value: Option<&String>, name: &str) -> Result<usize, Box<dyn Error>> {
    let value = value.ok_or_else(|| format!("{name} is required"))?;
    let parsed = value.parse::<usize>()?;
    if parsed == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }
    Ok(parsed)
}

fn latency(
    package_count: usize,
    iterations: usize,
    output_path: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let (environment, request) = fixture::build_fixture(package_count)?;
    let expected = execute_protocol_request(&environment, request.clone());
    let mut mismatches = 0;

    let cold_environment = environment.clone();
    let cold_start = Instant::now();
    let cold_runtime =
        PreparedRuntime::prepare(cold_environment, &request).expect("cold fixture must prepare");
    let cold_process_prepare = summarize(vec![cold_start.elapsed()]);
    black_box(cold_runtime);

    let direct_request = measure(iterations, || {
        let response = execute_protocol_request(&environment, request.clone());
        mismatches += usize::from(response != expected);
        black_box(response);
    });

    let prepared_construct = measure(iterations, || {
        let cloned = environment.clone();
        let runtime =
            PreparedRuntime::new(cloned).expect("fixture runtime identity must construct");
        black_box(runtime.generation());
    });

    let mut warm_scope_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let runtime =
            PreparedRuntime::new(environment.clone()).expect("fixture runtime must construct");
        let start = Instant::now();
        runtime.prime(&request).expect("fixture scope must prepare");
        warm_scope_samples.push(start.elapsed());
        black_box(runtime);
    }
    let warm_scope_preparation = summarize(warm_scope_samples);

    let cold_runtime_first_request = measure(iterations, || {
        let runtime =
            PreparedRuntime::new(environment.clone()).expect("fixture runtime must construct");
        let response = runtime.execute(request.clone());
        mismatches += usize::from(response != expected);
        black_box(response);
    });

    let runtime =
        PreparedRuntime::prepare(environment.clone(), &request).expect("fixture must prepare");
    let prepared_hit = measure(iterations.saturating_mul(4), || {
        let response = runtime.execute(request.clone());
        mismatches += usize::from(response != expected);
        black_box(response);
    });

    let mut narrower_request = request.clone();
    narrower_request.requested_scope.perspectives.clear();
    let narrower_expected = execute_protocol_request(&environment, narrower_request.clone());
    let prepared_scope_replacement = measure(iterations, || {
        let response = runtime.execute(narrower_request.clone());
        mismatches += usize::from(response != narrower_expected);
        black_box(response);
        let response = runtime.execute(request.clone());
        mismatches += usize::from(response != expected);
        black_box(response);
    });

    let report = LatencyReport {
        schema: "cantor-prepared-runtime-latency/0.2",
        package_count,
        iterations,
        cold_process_prepare,
        direct_request,
        prepared_construct,
        warm_scope_preparation,
        cold_runtime_first_request,
        prepared_scope_replacement,
        prepared_hit,
        exact_response_mismatches: mismatches,
        runtime_metrics_after_hits: runtime.metrics(),
    };
    emit(&report, output_path)
}

fn measure(mut iterations: usize, mut operation: impl FnMut()) -> DurationSummary {
    iterations = iterations.max(1);
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        operation();
        samples.push(start.elapsed());
    }
    summarize(samples)
}

fn summarize(mut samples: Vec<Duration>) -> DurationSummary {
    samples.sort_unstable();
    DurationSummary {
        samples: samples.len(),
        minimum_us: micros(samples[0]),
        median_us: micros(percentile(&samples, 50)),
        p95_us: micros(percentile(&samples, 95)),
        maximum_us: micros(samples[samples.len() - 1]),
    }
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let index = (samples.len() - 1).saturating_mul(percentile).div_ceil(100);
    samples[index]
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

#[cfg(feature = "dhat-heap")]
fn memory(
    mode: &str,
    package_count: usize,
    output_path: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let profiler = dhat::Profiler::builder().testing().build();
    let (environment, request) = fixture::build_fixture(package_count)?;
    let mut held_runtime = None;
    match mode {
        "baseline" => {
            black_box(&environment);
            black_box(&request);
        }
        "prepared" => {
            let runtime = PreparedRuntime::prepare(environment, &request)
                .map_err(|fault| format!("fixture preparation failed: {fault}"))?;
            let expected_digest = request.expected_environment_digest.clone();
            if runtime.generation().environment_digest != expected_digest {
                return Err("prepared generation digest mismatch".into());
            }
            let response = runtime.execute(request.clone());
            ensure_success_or_partial(&response)?;
            held_runtime = Some(runtime);
            black_box(response);
        }
        _ => return Err("memory mode must be baseline or prepared".into()),
    }
    black_box(&held_runtime);
    black_box(&request);
    let stats = dhat::HeapStats::get();
    let report = MemoryReport {
        schema: "cantor-prepared-runtime-memory/0.1",
        mode: mode.to_owned(),
        package_count,
        current_bytes: stats.curr_bytes,
        current_blocks: stats.curr_blocks,
        peak_bytes: stats.max_bytes,
        peak_blocks: stats.max_blocks,
        total_allocated_bytes: stats.total_bytes,
        total_allocated_blocks: stats.total_blocks,
    };
    emit(&report, output_path)?;
    drop(profiler);
    Ok(())
}

fn emit(value: &impl Serialize, output_path: Option<&String>) -> Result<(), Box<dyn Error>> {
    let encoded = serde_json::to_string_pretty(value)?;
    if let Some(output_path) = output_path {
        std::fs::write(output_path, format!("{encoded}\n"))?;
    } else {
        println!("{encoded}");
    }
    Ok(())
}

#[cfg(feature = "dhat-heap")]
fn ensure_success_or_partial(response: &ProtocolResponse) -> Result<(), Box<dyn Error>> {
    if matches!(
        response.status,
        cantor_core::ProtocolStatus::Success | cantor_core::ProtocolStatus::Partial
    ) {
        Ok(())
    } else {
        Err("prepared memory fixture returned a fault".into())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde_json::Value;
    use sha2::{Digest, Sha256};

    #[test]
    fn tracked_summary_has_three_complete_correct_shapes() {
        let summary: Value = serde_json::from_slice(include_bytes!(
            "../artifacts/2026-07-29_three_run_summary.json"
        ))
        .expect("tracked summary must decode");
        assert_eq!(
            summary["schema"],
            "cantor-prepared-runtime-evidence-summary/0.1"
        );
        assert_eq!(
            summary["correctness"]["measured_exact_response_mismatches"],
            0
        );
        let shapes = summary["shapes"]
            .as_array()
            .expect("summary shapes must be an array");
        assert_eq!(shapes.len(), 3);
        assert_eq!(
            shapes
                .iter()
                .map(|shape| shape["package_count"]
                    .as_u64()
                    .expect("count must be numeric"))
                .collect::<Vec<_>>(),
            vec![1, 32, 256]
        );
        for shape in shapes {
            assert_eq!(shape["exact_response_mismatches"], 0);
            let speedup = shape["median_hit_speedup_range"][0]
                .as_f64()
                .expect("speedup must be numeric");
            assert!(speedup > 1.0);
            let retained_ratio = shape["memory"]["retained_ratio_range"][1]
                .as_f64()
                .expect("memory ratio must be numeric");
            assert!(retained_ratio > 1.0);
        }
    }

    #[test]
    fn tracked_summary_hashes_every_raw_measurement() {
        let summary: Value = serde_json::from_slice(include_bytes!(
            "../artifacts/2026-07-29_three_run_summary.json"
        ))
        .expect("tracked summary must decode");
        let artifacts = summary["raw_artifacts"]
            .as_array()
            .expect("raw artifact manifest must be an array");
        assert_eq!(artifacts.len(), 27);
        for artifact in artifacts {
            let path = artifact["path"]
                .as_str()
                .expect("artifact path must be text");
            assert!(Path::new(path).is_file(), "artifact is missing: {path}");
            let bytes = fs::read(path).expect("artifact must be readable");
            assert_eq!(
                bytes.len() as u64,
                artifact["bytes"]
                    .as_u64()
                    .expect("artifact byte count must be numeric")
            );
            let actual = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            assert_eq!(
                actual,
                artifact["sha256"]
                    .as_str()
                    .expect("artifact digest must be text")
            );
        }
    }

    #[test]
    fn evidence_manifest_hashes_authority_implementation_and_measurements() {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root must resolve");
        let manifest: Value = serde_json::from_slice(include_bytes!(
            "../artifacts/prepared_runtime_evidence_manifest.json"
        ))
        .expect("evidence manifest must decode");
        assert_eq!(
            manifest["schema"],
            "cantor-prepared-runtime-evidence-manifest/0.1"
        );
        let artifacts = manifest["artifacts"]
            .as_array()
            .expect("manifest artifacts must be an array");
        assert_eq!(artifacts.len(), 48);
        for artifact in artifacts {
            let path = artifact["path"]
                .as_str()
                .expect("artifact path must be text");
            assert!(
                !Path::new(path).is_absolute(),
                "manifest paths must remain clone-portable: {path}"
            );
            let bytes =
                fs::read(repository_root.join(path)).expect("manifest artifact must be readable");
            assert_eq!(
                bytes.len() as u64,
                artifact["bytes"]
                    .as_u64()
                    .expect("artifact byte count must be numeric")
            );
            let actual = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            assert_eq!(
                actual,
                artifact["sha256"]
                    .as_str()
                    .expect("artifact digest must be text"),
                "manifest digest mismatch for {path}"
            );
        }
    }
}
