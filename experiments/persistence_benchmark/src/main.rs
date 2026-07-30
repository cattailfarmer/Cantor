mod fixture;
mod stores;

use std::{
    env, fs,
    hint::black_box,
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use cantor_core::{
    EmbeddedRuntimeEnvironment, ProtocolRequest, ProtocolResponse, embedded_environment_digest,
    execute_protocol_request, verify_protocol_response_against_environment,
};
use serde::Serialize;

use crate::{
    fixture::build_fixture,
    stores::{load_json, load_redb, load_sqlite, write_json, write_redb, write_sqlite},
};

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    report_version: &'static str,
    captured_at_epoch_milliseconds: u128,
    machine: String,
    operating_system: String,
    rustc: String,
    cargo: String,
    rusqlite_version: &'static str,
    redb_version: &'static str,
    cache_boundary: &'static str,
    corpus_boundary: &'static str,
    scenarios: Vec<ScenarioReport>,
}

#[derive(Debug, Serialize)]
struct ScenarioReport {
    package_count: usize,
    canonical_json_bytes: u64,
    environment_digest: String,
    load_iterations: usize,
    query_iterations: usize,
    candidates: Vec<CandidateReport>,
}

#[derive(Debug, Serialize)]
struct CandidateReport {
    candidate: &'static str,
    post_write_physical_bytes: u64,
    post_load_physical_bytes: u64,
    post_load_size_ratio_to_json: f64,
    durable_write_microseconds: u128,
    load_microseconds: Distribution,
    query_microseconds: Distribution,
    digest_equal: bool,
    response_equal: bool,
}

#[derive(Debug, Serialize)]
struct Distribution {
    samples: usize,
    minimum: u128,
    median: u128,
    p95: u128,
    maximum: u128,
}

type Loader = fn(&Path) -> Result<EmbeddedRuntimeEnvironment, Box<dyn std::error::Error>>;
type Writer = fn(&Path, &EmbeddedRuntimeEnvironment) -> Result<(), Box<dyn std::error::Error>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: cantor-persistence-benchmark <output-root>")?;
    fs::create_dir_all(&output_root)?;
    let captured = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let run_directory = output_root.join(format!("run-{captured}"));
    fs::create_dir(&run_directory)?;

    let mut scenarios = Vec::new();
    for package_count in [1_usize, 32, 256] {
        scenarios.push(run_scenario(&run_directory, package_count)?);
    }
    let report = BenchmarkReport {
        report_version: "cantor-persistence-benchmark/0.4",
        captured_at_epoch_milliseconds: captured,
        machine: env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_owned()),
        operating_system: format!("{} {}", env::consts::OS, env::consts::ARCH),
        rustc: command_version("rustc")?,
        cargo: command_version("cargo")?,
        rusqlite_version: "0.40.1",
        redb_version: "4.1.0",
        cache_boundary: "repeated local reopen and reconstruction; operating-system page cache is not cleared",
        corpus_boundary: "synthetic public-key fixture packages with one term unit and one source each",
        scenarios,
    };
    let report_path = run_directory.join("report.json");
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", report_path.display());
    Ok(())
}

fn run_scenario(
    directory: &Path,
    package_count: usize,
) -> Result<ScenarioReport, Box<dyn std::error::Error>> {
    let scenario_directory = directory.join(format!("{package_count}-packages"));
    fs::create_dir(&scenario_directory)?;
    let (environment, request) = build_fixture(package_count)?;
    let environment_digest = embedded_environment_digest(&environment)?;
    let oracle = execute_protocol_request(&environment, request.clone());
    verify_protocol_response_against_environment(&environment, &request, &oracle).map_err(
        |fault| {
            format!(
                "oracle verification failed ({}): {}",
                fault.code, fault.message
            )
        },
    )?;
    let load_iterations = match package_count {
        1 => 50,
        32 => 25,
        _ => 10,
    };
    let query_iterations = match package_count {
        1 => 100,
        32 => 50,
        _ => 20,
    };
    let canonical_json_bytes = serde_json::to_vec(&environment)?.len() as u64;
    let candidates = vec![
        benchmark_candidate(
            "json",
            &scenario_directory.join("environment.json"),
            &environment,
            &request,
            &oracle,
            write_json,
            load_json,
            canonical_json_bytes,
            load_iterations,
            query_iterations,
        )?,
        benchmark_candidate(
            "sqlite",
            &scenario_directory.join("environment.sqlite3"),
            &environment,
            &request,
            &oracle,
            write_sqlite,
            load_sqlite,
            canonical_json_bytes,
            load_iterations,
            query_iterations,
        )?,
        benchmark_candidate(
            "redb",
            &scenario_directory.join("environment.redb"),
            &environment,
            &request,
            &oracle,
            write_redb,
            load_redb,
            canonical_json_bytes,
            load_iterations,
            query_iterations,
        )?,
    ];
    Ok(ScenarioReport {
        package_count,
        canonical_json_bytes,
        environment_digest: environment_digest.value,
        load_iterations,
        query_iterations,
        candidates,
    })
}

#[allow(clippy::too_many_arguments)]
fn benchmark_candidate(
    candidate: &'static str,
    path: &Path,
    source: &EmbeddedRuntimeEnvironment,
    request: &ProtocolRequest,
    oracle: &ProtocolResponse,
    writer: Writer,
    loader: Loader,
    canonical_json_bytes: u64,
    load_iterations: usize,
    query_iterations: usize,
) -> Result<CandidateReport, Box<dyn std::error::Error>> {
    let started = Instant::now();
    writer(path, source)?;
    let durable_write_microseconds = started.elapsed().as_micros();
    let post_write_physical_bytes = fs::metadata(path)?.len();

    let mut load_samples = Vec::with_capacity(load_iterations);
    for _ in 0..load_iterations {
        let started = Instant::now();
        let loaded = loader(path)?;
        load_samples.push(started.elapsed().as_micros());
        black_box(loaded);
    }
    let loaded = loader(path)?;
    let digest_equal =
        embedded_environment_digest(&loaded)? == embedded_environment_digest(source)?;
    if !digest_equal || loaded != *source {
        return Err(format!("{candidate} reconstruction differs from source environment").into());
    }
    let reconstructed_response = execute_protocol_request(&loaded, request.clone());
    let response_equal = reconstructed_response == *oracle;
    if !response_equal {
        return Err(format!("{candidate} response differs from direct oracle").into());
    }
    verify_protocol_response_against_environment(&loaded, request, &reconstructed_response)
        .map_err(|fault| {
            format!(
                "{candidate} response verification failed ({}): {}",
                fault.code, fault.message
            )
        })?;

    let mut query_samples = Vec::with_capacity(query_iterations);
    for _ in 0..query_iterations {
        let started = Instant::now();
        let response = execute_protocol_request(&loaded, request.clone());
        query_samples.push(started.elapsed().as_micros());
        if response != *oracle {
            return Err(format!("{candidate} repeated query response drifted").into());
        }
        black_box(response);
    }
    let post_load_physical_bytes = fs::metadata(path)?.len();
    Ok(CandidateReport {
        candidate,
        post_write_physical_bytes,
        post_load_physical_bytes,
        post_load_size_ratio_to_json: post_load_physical_bytes as f64 / canonical_json_bytes as f64,
        durable_write_microseconds,
        load_microseconds: distribution(load_samples),
        query_microseconds: distribution(query_samples),
        digest_equal,
        response_equal,
    })
}

fn distribution(mut samples: Vec<u128>) -> Distribution {
    samples.sort_unstable();
    let p95_index = ((samples.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(samples.len() - 1);
    Distribution {
        samples: samples.len(),
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use cantor_core::{
        ExitClass, ProtocolOperation, ProtocolOutcome, ProtocolStatus, SemanticFabric,
        admit_package, execute_query,
    };
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = env::temp_dir().join(format!(
                "cantor-persistence-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn every_candidate_reconstructs_the_exact_signed_environment()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::create("round-trip")?;
        let (environment, request) = build_fixture(3)?;
        let oracle = execute_protocol_request(&environment, request.clone());

        for (name, extension, writer, loader) in candidates() {
            let path = directory.path().join(format!("{name}.{extension}"));
            writer(&path, &environment)?;
            let reconstructed = loader(&path)?;
            assert_eq!(reconstructed, environment, "{name} environment");
            assert_eq!(
                embedded_environment_digest(&reconstructed)?,
                request.expected_environment_digest,
                "{name} digest"
            );
            assert_eq!(
                execute_protocol_request(&reconstructed, request.clone()),
                oracle,
                "{name} response"
            );
        }
        Ok(())
    }

    #[test]
    fn persisted_tampering_never_becomes_semantic_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::create("tamper")?;
        let (environment, request) = build_fixture(3)?;
        let mut tampered = environment.clone();
        tampered.packages[0].content.sources[0].bytes[0] ^= 1;

        for (name, extension, writer, loader) in candidates() {
            let path = directory.path().join(format!("{name}.{extension}"));
            writer(&path, &tampered)?;
            let reconstructed = loader(&path)?;
            let response = execute_protocol_request(&reconstructed, request.clone());
            assert_eq!(response.status, ProtocolStatus::Fault, "{name} status");
            assert_eq!(
                response.exit_class,
                ExitClass::TrustFailure,
                "{name} exit class"
            );
            assert!(
                response
                    .faults
                    .iter()
                    .any(|fault| fault.code == "environment_digest_mismatch"),
                "{name} must expose the digest mismatch"
            );
            assert!(!response.proof.expected_package_set_verified);
        }
        Ok(())
    }

    #[test]
    fn malformed_physical_artifacts_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::create("malformed")?;
        let (environment, _) = build_fixture(1)?;

        for (name, extension, writer, loader) in candidates() {
            let path = directory.path().join(format!("{name}.{extension}"));
            writer(&path, &environment)?;
            fs::write(&path, b"not a valid persistence artifact")?;
            assert!(loader(&path).is_err(), "{name} accepted malformed bytes");
        }
        Ok(())
    }

    #[test]
    fn sqlite_inspection_metadata_must_match_the_signed_package()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::create("sqlite-metadata")?;
        let (environment, _) = build_fixture(3)?;
        let cases = [
            (
                "digest",
                "UPDATE package SET package_digest = '00' WHERE ordinal = 1",
                "digest metadata differs",
            ),
            (
                "identity",
                "UPDATE package SET package_id = 'package:substituted' WHERE ordinal = 1",
                "identity metadata",
            ),
            (
                "ordinal",
                "UPDATE package SET ordinal = 10 WHERE ordinal = 1",
                "not contiguous",
            ),
        ];
        for (name, mutation, expected_fault) in cases {
            let path = directory.path().join(format!("{name}.sqlite3"));
            write_sqlite(&path, &environment)?;
            let connection = rusqlite::Connection::open(&path)?;
            connection.execute(mutation, [])?;
            connection.close().map_err(|(_, error)| error)?;

            let error = load_sqlite(&path)
                .expect_err("SQLite inspection metadata drift must fail")
                .to_string();
            assert!(error.contains(expected_fault), "{name}: {error}");
        }
        Ok(())
    }

    #[test]
    fn redb_ordinal_metadata_must_remain_contiguous() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::create("redb-metadata")?;
        let path = directory.path().join("environment.redb");
        let (environment, _) = build_fixture(3)?;
        write_redb(&path, &environment)?;

        let database = redb::Database::open(&path)?;
        let transaction = database.begin_write()?;
        {
            let mut table = transaction.open_table(crate::stores::REDB_PACKAGES)?;
            let bytes = table
                .remove(1_u64)?
                .ok_or("redb fixture ordinal 1 missing")?
                .value()
                .to_vec();
            table.insert(10_u64, bytes.as_slice())?;
        }
        transaction.commit()?;
        drop(database);

        let error = load_redb(&path)
            .expect_err("redb ordinal metadata drift must fail")
            .to_string();
        assert!(error.contains("not contiguous"));
        Ok(())
    }

    #[test]
    fn tracked_reports_mechanically_support_the_decision_summary()
    -> Result<(), Box<dyn std::error::Error>> {
        let report_bytes: [&[u8]; 3] = [
            include_bytes!("../artifacts/run_1785364060549_report.json"),
            include_bytes!("../artifacts/run_1785364063272_report.json"),
            include_bytes!("../artifacts/run_1785364066001_report.json"),
        ];
        let reports = report_bytes
            .iter()
            .map(|bytes| serde_json::from_slice::<Value>(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let summary: Value = serde_json::from_slice(include_bytes!(
            "../artifacts/2026-07-29_three_run_summary.json"
        ))?;

        assert_eq!(
            number(&summary["method_boundary"]["runs"])?,
            reports.len() as u64
        );
        assert_eq!(
            number(&summary["correctness"]["candidate_scale_combinations"])?,
            9
        );
        assert_eq!(
            number(&summary["correctness"]["independent_runs"])?,
            reports.len() as u64
        );
        for field in [
            "digest_failures",
            "environment_equality_failures",
            "response_equality_failures",
        ] {
            assert_eq!(number(&summary["correctness"][field])?, 0, "{field}");
        }

        let source_reports = array(&summary["source_reports"])?;
        assert_eq!(source_reports.len(), reports.len());
        for ((bytes, report), source) in report_bytes
            .iter()
            .zip(reports.iter())
            .zip(source_reports.iter())
        {
            assert_eq!(
                number(&source["captured_at_epoch_milliseconds"])?,
                number(&report["captured_at_epoch_milliseconds"])?
            );
            let digest = Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            assert_eq!(text_value(&source["sha256"])?, digest);
        }

        for report in &reports {
            assert_eq!(
                text_value(&report["report_version"])?,
                "cantor-persistence-benchmark/0.4"
            );
        }

        let summary_scenarios = array(&summary["scenarios"])?;
        assert_eq!(summary_scenarios.len(), 3);
        assert!(
            reports
                .iter()
                .all(|report| array(&report["scenarios"])
                    .is_ok_and(|scenarios| scenarios.len() == 3))
        );
        for summary_scenario in summary_scenarios {
            let package_count = number(&summary_scenario["package_count"])?;
            let report_scenarios = reports
                .iter()
                .map(|report| scenario(report, package_count))
                .collect::<Result<Vec<_>, _>>()?;
            let canonical_sizes = report_scenarios
                .iter()
                .map(|scenario| number(&scenario["canonical_json_bytes"]))
                .collect::<Result<Vec<_>, _>>()?;
            assert!(canonical_sizes.windows(2).all(|pair| pair[0] == pair[1]));
            assert_eq!(
                number(&summary_scenario["canonical_json_bytes"])?,
                canonical_sizes[0]
            );

            for summary_candidate in array(&summary_scenario["candidates"])? {
                let candidate_name = text_value(&summary_candidate["candidate"])?;
                let report_candidates = report_scenarios
                    .iter()
                    .map(|scenario| candidate(scenario, candidate_name))
                    .collect::<Result<Vec<_>, _>>()?;
                assert!(report_scenarios.iter().all(|scenario| {
                    array(&scenario["candidates"]).is_ok_and(|candidates| candidates.len() == 3)
                }));

                assert_range(
                    &summary_candidate["load_median_microseconds_range"],
                    report_candidates
                        .iter()
                        .map(|candidate| number(&candidate["load_microseconds"]["median"]))
                        .collect::<Result<Vec<_>, _>>()?,
                )?;
                assert_eq!(
                    number(&summary_candidate["load_p95_microseconds_max"])?,
                    report_candidates
                        .iter()
                        .map(|candidate| number(&candidate["load_microseconds"]["p95"]))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .max()
                        .ok_or("missing load p95")?
                );
                assert_range(
                    &summary_candidate["durable_write_microseconds_range"],
                    report_candidates
                        .iter()
                        .map(|candidate| number(&candidate["durable_write_microseconds"]))
                        .collect::<Result<Vec<_>, _>>()?,
                )?;
                assert_range(
                    &summary_candidate["query_median_microseconds_range"],
                    report_candidates
                        .iter()
                        .map(|candidate| number(&candidate["query_microseconds"]["median"]))
                        .collect::<Result<Vec<_>, _>>()?,
                )?;

                let post_load_sizes = report_candidates
                    .iter()
                    .map(|candidate| number(&candidate["post_load_physical_bytes"]))
                    .collect::<Result<Vec<_>, _>>()?;
                assert!(post_load_sizes.windows(2).all(|pair| pair[0] == pair[1]));
                assert_eq!(
                    number(&summary_candidate["post_load_bytes"])?,
                    post_load_sizes[0]
                );
                if !summary_candidate["post_write_bytes"].is_null() {
                    let post_write_sizes = report_candidates
                        .iter()
                        .map(|candidate| number(&candidate["post_write_physical_bytes"]))
                        .collect::<Result<Vec<_>, _>>()?;
                    assert!(post_write_sizes.windows(2).all(|pair| pair[0] == pair[1]));
                    assert_eq!(
                        number(&summary_candidate["post_write_bytes"])?,
                        post_write_sizes[0]
                    );
                }
                let summary_ratio = summary_candidate["size_ratio_to_json"]
                    .as_f64()
                    .ok_or("summary size ratio must be a number")?;
                let expected_ratios = report_candidates
                    .iter()
                    .map(|candidate| {
                        candidate["post_load_size_ratio_to_json"]
                            .as_f64()
                            .ok_or("report size ratio must be a number")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                assert!(
                    expected_ratios
                        .iter()
                        .all(|ratio| (ratio - expected_ratios[0]).abs() < f64::EPSILON)
                );
                assert_eq!(
                    summary_ratio,
                    (expected_ratios[0] * 1_000.0).round() / 1_000.0
                );
                assert!(report_candidates.iter().all(|candidate| {
                    candidate["digest_equal"].as_bool() == Some(true)
                        && candidate["response_equal"].as_bool() == Some(true)
                }));
            }
        }
        Ok(())
    }

    #[test]
    fn tracked_runtime_decomposition_supports_the_request_lifetime_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let report_bytes: [&[u8]; 3] = [
            include_bytes!("../artifacts/runtime_decomposition_run_1785364192582.json"),
            include_bytes!("../artifacts/runtime_decomposition_run_1785364194692.json"),
            include_bytes!("../artifacts/runtime_decomposition_run_1785364196790.json"),
        ];
        let reports = report_bytes
            .iter()
            .map(|bytes| serde_json::from_slice::<Value>(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let summary: Value = serde_json::from_slice(include_bytes!(
            "../artifacts/2026-07-29_runtime_decomposition_summary.json"
        ))?;
        assert_eq!(
            number(&summary["method_boundary"]["independent_runs"])?,
            reports.len() as u64
        );

        let source_reports = array(&summary["source_reports"])?;
        assert_eq!(source_reports.len(), reports.len());
        for ((bytes, report), source) in report_bytes
            .iter()
            .zip(reports.iter())
            .zip(source_reports.iter())
        {
            assert_eq!(
                text_value(&report["report_version"])?,
                "cantor-runtime-decomposition/0.2"
            );
            assert_eq!(
                number(&source["captured_at_epoch_milliseconds"])?,
                number(&report["captured_at_epoch_milliseconds"])?
            );
            let digest = Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            assert_eq!(text_value(&source["sha256"])?, digest);
        }

        let summary_scenarios = array(&summary["scenarios"])?;
        assert_eq!(summary_scenarios.len(), 3);
        for summary_scenario in summary_scenarios {
            let package_count = number(&summary_scenario["package_count"])?;
            let report_scenarios = reports
                .iter()
                .map(|report| scenario(report, package_count))
                .collect::<Result<Vec<_>, _>>()?;
            for report_scenario in &report_scenarios {
                assert!(
                    report_scenario["prepared_query_equals_protocol_query"].as_bool() == Some(true)
                        && report_scenario["repeated_protocol_response_equal"].as_bool()
                            == Some(true)
                );
            }
            assert_runtime_stage(
                summary_scenario,
                &report_scenarios,
                "environment_digest_microseconds",
                "environment_digest_median_microseconds_range",
                "environment_digest_p95_microseconds_max",
            )?;
            assert_runtime_stage(
                summary_scenario,
                &report_scenarios,
                "admit_and_build_fabric_microseconds",
                "admit_and_build_median_microseconds_range",
                "admit_and_build_p95_microseconds_max",
            )?;
            assert_runtime_stage(
                summary_scenario,
                &report_scenarios,
                "prepared_query_microseconds",
                "prepared_query_median_microseconds_range",
                "prepared_query_p95_microseconds_max",
            )?;
            assert_runtime_stage(
                summary_scenario,
                &report_scenarios,
                "full_protocol_microseconds",
                "full_protocol_median_microseconds_range",
                "full_protocol_p95_microseconds_max",
            )?;
        }
        Ok(())
    }

    #[test]
    fn phase6_evidence_manifest_hashes_every_authority_and_measurement_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest: Value =
            serde_json::from_slice(include_bytes!("../artifacts/phase6_evidence_manifest.json"))?;
        assert_eq!(
            text_value(&manifest["manifest_version"])?,
            "cantor-phase6-evidence-manifest/0.1"
        );
        assert_eq!(text_value(&manifest["hash_algorithm"])?, "SHA-256");
        let files = array(&manifest["files"])?;
        assert_eq!(files.len(), 21);
        let project_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut paths = std::collections::BTreeSet::new();
        for file in files {
            let relative = text_value(&file["path"])?;
            let relative_path = Path::new(relative);
            assert!(!relative_path.is_absolute());
            assert!(!relative_path.components().any(|component| matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )));
            assert!(paths.insert(relative.to_owned()), "duplicate manifest path");
            let bytes = fs::read(project_root.join(relative_path))?;
            let digest = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            assert_eq!(text_value(&file["sha256"])?, digest, "{relative}");
        }
        assert_eq!(
            text_value(&manifest["verification"]["production_dependency_change"])?,
            "none"
        );
        Ok(())
    }

    #[test]
    fn immutable_prepared_fabric_is_send_sync_and_read_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SemanticFabric>();

        let (environment, request) = build_fixture(32)?;
        let query = match &request.request {
            ProtocolOperation::Query { query } => query.as_ref().clone(),
            ProtocolOperation::Inspect { .. } => return Err("fixture must be a query".into()),
        };
        let admitted = environment
            .packages
            .iter()
            .map(|package| {
                admit_package(
                    package,
                    &environment.trust_store,
                    &request.requested_scope,
                    environment.now_epoch_seconds,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let fabric = std::sync::Arc::new(
            SemanticFabric::from_admitted(admitted)
                .map_err(|fault| format!("{:?}: {}", fault.kind, fault.message))?,
        );
        let expected = execute_query(&fabric, &query)
            .map_err(|fault| format!("{:?}: {}", fault.kind, fault.message))?;
        let handles = (0..8)
            .map(|_| {
                let fabric = std::sync::Arc::clone(&fabric);
                let query = query.clone();
                let expected = expected.clone();
                std::thread::spawn(move || {
                    for _ in 0..16 {
                        let result = execute_query(&fabric, &query)
                            .map_err(|fault| format!("{:?}: {}", fault.kind, fault.message))?;
                        if result != expected {
                            return Err("prepared concurrent query drifted".to_owned());
                        }
                    }
                    Ok::<_, String>(())
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle
                .join()
                .map_err(|_| "prepared query worker panicked")?
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        }

        let protocol = execute_protocol_request(&environment, request);
        let ProtocolOutcome::Query(protocol_query) = protocol.result else {
            return Err("full protocol did not return a query result".into());
        };
        assert_eq!(expected, protocol_query);
        Ok(())
    }

    #[test]
    fn phase6_sjs_lineage_is_closed_and_identity_distinct() -> Result<(), Box<dyn std::error::Error>>
    {
        let project_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let read = |relative: &str| -> Result<String, Box<dyn std::error::Error>> {
            Ok(fs::read_to_string(project_root.join(relative))?)
        };
        let source_manifest = read(
            "source_documents/2026-07-29_cantor_persistence_decision/Source_Document_Manifest.sop",
        )?;
        let source_bytes = fs::read(project_root.join(
            "source_documents/2026-07-29_cantor_persistence_decision/Dictated_Cantor_Persistence_Decision_Source.sop",
        ))?;
        let exploded =
            read("specifications/exploded/Cantor_Persistence_Evidence_Gate.exploded.sop")?;
        let canonical = read("specifications/Cantor_Persistence_Evidence_Gate.sop")?;
        let justification =
            read("justifications/Cantor_Persistence_Evidence_Gate_Justification.sop")?;
        let slice = read("feature_support/slices/Phase6_Persistence_Decision.sop")?;
        let solution = read("solutions/Phase6_Persistence_Decision_Solution.sop")?;

        let source_snapshot_uuid = "d8d76cba-5a0d-4510-9b86-52faf2332af6";
        let exploded_uuid = "8249ec0f-218e-41b3-9043-63e915ab8403";
        let canonical_uuid = "f5157d4d-eea6-4a3a-af5b-12e2de5a4a4d";
        let justification_uuid = "9d163caa-e11c-487b-aa18-550797523e52";
        let signature_uuid = "7a23c8ec-f8f4-4ec6-af24-06683131d3c8";
        let slice_uuid = "07beb0a5-b9fc-48fa-817d-df7cb72bf54d";
        let solution_uuid = "a6fe47fc-54bd-443a-af25-9deff7d58896";

        assert!(source_manifest.contains(source_snapshot_uuid));
        assert!(
            source_manifest
                .contains("34B116D18C6CF69A1307C39B73B685E67C214283C1C06454B2EDFF5A761F63E9")
        );
        assert!(source_manifest.contains("[byte_length] is 990"));
        assert_eq!(source_bytes.len(), 990);
        assert!(exploded.contains(source_snapshot_uuid));
        assert!(exploded.contains(exploded_uuid));
        for identity in [
            source_snapshot_uuid,
            exploded_uuid,
            canonical_uuid,
            justification_uuid,
            signature_uuid,
        ] {
            assert!(canonical.contains(identity), "canonical omits {identity}");
        }
        assert!(canonical.contains("[signature_status] is valid"));
        assert!(justification.contains("specifications\\Cantor_Persistence_Evidence_Gate.sop"));
        assert!(justification.contains(justification_uuid));
        assert!(justification.contains(solution_uuid));
        assert!(slice.contains(slice_uuid));
        assert!(!slice.contains(&format!("[slice_uuid] is {solution_uuid}")));
        assert!(solution.contains(solution_uuid));

        let identities = [
            source_snapshot_uuid,
            exploded_uuid,
            canonical_uuid,
            justification_uuid,
            signature_uuid,
            slice_uuid,
            solution_uuid,
        ];
        assert_eq!(
            identities
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            identities.len()
        );
        Ok(())
    }

    fn candidates() -> [(&'static str, &'static str, Writer, Loader); 3] {
        [
            ("json", "json", write_json, load_json),
            ("sqlite", "sqlite3", write_sqlite, load_sqlite),
            ("redb", "redb", write_redb, load_redb),
        ]
    }

    fn scenario(report: &Value, package_count: u64) -> Result<&Value, Box<dyn std::error::Error>> {
        array(&report["scenarios"])?
            .iter()
            .find(|scenario| {
                number(&scenario["package_count"]).is_ok_and(|value| value == package_count)
            })
            .ok_or_else(|| format!("report scenario {package_count} missing").into())
    }

    fn candidate<'a>(
        scenario: &'a Value,
        name: &str,
    ) -> Result<&'a Value, Box<dyn std::error::Error>> {
        array(&scenario["candidates"])?
            .iter()
            .find(|candidate| text_value(&candidate["candidate"]).is_ok_and(|value| value == name))
            .ok_or_else(|| format!("candidate {name} missing").into())
    }

    fn assert_range(
        summary_range: &Value,
        values: Vec<u64>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let range = array(summary_range)?;
        assert_eq!(range.len(), 2);
        assert_eq!(
            number(&range[0])?,
            *values.iter().min().ok_or("empty evidence range")?
        );
        assert_eq!(
            number(&range[1])?,
            *values.iter().max().ok_or("empty evidence range")?
        );
        Ok(())
    }

    fn assert_runtime_stage(
        summary_scenario: &Value,
        report_scenarios: &[&Value],
        report_field: &str,
        summary_range_field: &str,
        summary_p95_field: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut medians = Vec::with_capacity(report_scenarios.len());
        let mut p95s = Vec::with_capacity(report_scenarios.len());
        for scenario in report_scenarios {
            let distribution = &scenario[report_field];
            let ordered = [
                number(&distribution["minimum"])?,
                number(&distribution["median"])?,
                number(&distribution["p95"])?,
                number(&distribution["maximum"])?,
            ];
            assert!(ordered.windows(2).all(|pair| pair[0] <= pair[1]));
            medians.push(ordered[1]);
            p95s.push(ordered[2]);
        }
        assert_range(&summary_scenario[summary_range_field], medians)?;
        assert_eq!(
            number(&summary_scenario[summary_p95_field])?,
            p95s.into_iter().max().ok_or("missing runtime p95")?
        );
        Ok(())
    }

    fn array(value: &Value) -> Result<&Vec<Value>, Box<dyn std::error::Error>> {
        value.as_array().ok_or_else(|| "expected JSON array".into())
    }

    fn number(value: &Value) -> Result<u64, Box<dyn std::error::Error>> {
        value
            .as_u64()
            .ok_or_else(|| "expected unsigned JSON number".into())
    }

    fn text_value(value: &Value) -> Result<&str, Box<dyn std::error::Error>> {
        value.as_str().ok_or_else(|| "expected JSON string".into())
    }
}
