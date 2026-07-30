use std::env;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Instant;

use cantor_core::{
    EmbeddedRuntimeEnvironment, PackageCompiler, PreparedRuntime, ProtocolRequest,
    SopCorpusManifest, SopDocumentInput, SopSigningKeys, build_sop_corpus,
    execute_protocol_request, lower_sop_corpus,
};
use ed25519_dalek::SigningKey;
use serde::Serialize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse(env::args().skip(1).collect())?;
    let manifest_path = arguments.manifest.canonicalize()?;
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: SopCorpusManifest = serde_json::from_slice(&manifest_bytes)?;
    let source_root = manifest_path
        .parent()
        .ok_or("manifest has no parent")?
        .join(&manifest.source_root)
        .canonicalize()?;
    let documents = load_documents(&source_root, &manifest)?;
    let lowered = lower_sop_corpus(&manifest, documents.clone())
        .map_err(|faults| format!("lowering failed: {faults:?}"))?;
    let compiler = PackageCompiler::new(
        manifest.compiler.compiler_id.clone(),
        manifest.compiler.compiler_version.clone(),
        manifest.compiler.authority_signer_id.clone(),
        manifest.compiler.compiler_signer_id.clone(),
        SigningKey::from_bytes(&[71_u8; 32]),
        SigningKey::from_bytes(&[73_u8; 32]),
    );
    let built = build_sop_corpus(
        &manifest,
        documents.clone(),
        SopSigningKeys {
            authority: SigningKey::from_bytes(&[71_u8; 32]),
            compiler: SigningKey::from_bytes(&[73_u8; 32]),
        },
    )
    .map_err(|faults| format!("corpus build failed: {faults:?}"))?;
    let request = built
        .requests
        .iter()
        .find(|request| request.name == "query-semantic-unit")
        .ok_or("semantic-unit request is missing")?
        .request
        .clone();
    let direct = execute_protocol_request(&built.environment, request.clone());
    if direct.exit_class.code() != 0 {
        return Err(format!("direct query failed: {:?}", direct.faults).into());
    }
    let environment_bytes = serde_json::to_vec(&built.environment)?;
    let request_bytes = serde_json::to_vec(&request)?;
    let runtime = PreparedRuntime::new(built.environment.clone())
        .map_err(|fault| format!("prepared runtime failed: {fault:?}"))?;
    let cold_prepared = runtime.execute(request.clone());
    if cold_prepared != direct {
        return Err("prepared cold response differs from direct response".into());
    }

    let parse_lower = measure(arguments.iterations, || {
        let value = lower_sop_corpus(&manifest, documents.clone())
            .unwrap_or_else(|faults| panic!("measured lowering failed: {faults:?}"));
        black_box(value.unit_count);
    });
    let compile_signed_package = measure(arguments.iterations, || {
        let package = compiler
            .compile(lowered.package_input.clone())
            .unwrap_or_else(|fault| panic!("measured package compile failed: {fault}"));
        black_box(package.package_id);
    });
    let full_build_preflight = measure(arguments.iterations, || {
        let value = build_sop_corpus(
            &manifest,
            documents.clone(),
            SopSigningKeys {
                authority: SigningKey::from_bytes(&[71_u8; 32]),
                compiler: SigningKey::from_bytes(&[73_u8; 32]),
            },
        )
        .unwrap_or_else(|faults| panic!("measured corpus build failed: {faults:?}"));
        black_box(value.environment);
    });
    let environment_load = measure(arguments.iterations, || {
        let environment: EmbeddedRuntimeEnvironment =
            serde_json::from_slice(&environment_bytes).expect("environment load must succeed");
        let request: ProtocolRequest =
            serde_json::from_slice(&request_bytes).expect("request load must succeed");
        black_box((environment, request));
    });
    let direct_query = measure(arguments.iterations, || {
        let response = execute_protocol_request(&built.environment, request.clone());
        assert_eq!(response, direct);
        black_box(response);
    });
    let prepared_hit = measure(arguments.iterations, || {
        let response = runtime.execute(request.clone());
        assert_eq!(response, direct);
        black_box(response);
    });
    let metrics = runtime.metrics();
    let report = Report {
        profile: "cantor-self-hosted-corpus-benchmark/0.1",
        iterations: arguments.iterations,
        source_count: built.source_count,
        unit_count: built.unit_count,
        relation_count: built.relation_count,
        source_bytes: documents.iter().map(|document| document.bytes.len()).sum(),
        environment_bytes: environment_bytes.len(),
        request_bytes: request_bytes.len(),
        correctness_mismatches: 0,
        prepared_projection_preparations: metrics.projection_preparations,
        prepared_projection_hits: metrics.projection_hits,
        measurements_microseconds: Measurements {
            parse_lower,
            compile_signed_package,
            full_build_preflight,
            environment_load,
            direct_query,
            prepared_hit,
        },
        limitations: vec![
            "one Windows host and one release build profile".to_owned(),
            "three reviewed Cantor specifications rather than a terabyte-scale corpus".to_owned(),
            "in-process latency rather than service transport latency".to_owned(),
            "fixed public benchmark-only signing seeds".to_owned(),
        ],
    };
    let mut bytes = serde_json::to_vec(&report)?;
    bytes.push(b'\n');
    if let Some(output) = &arguments.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        use std::io::Write;
        file.write_all(&bytes)?;
        file.sync_all()?;
    } else {
        use std::io::Write;
        std::io::stdout().lock().write_all(&bytes)?;
    }
    Ok(())
}

fn load_documents(
    source_root: &Path,
    manifest: &SopCorpusManifest,
) -> Result<Vec<SopDocumentInput>, Box<dyn std::error::Error>> {
    manifest
        .documents
        .iter()
        .map(|document| {
            Ok(SopDocumentInput {
                document_id: document.document_id.clone(),
                path: document.path.clone(),
                bytes: fs::read(source_root.join(&document.path))?,
            })
        })
        .collect()
}

fn measure(iterations: usize, mut operation: impl FnMut()) -> Distribution {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        operation();
        samples.push(started.elapsed().as_secs_f64() * 1_000_000.0);
    }
    samples.sort_by(f64::total_cmp);
    Distribution {
        minimum: samples[0],
        median: quantile(&samples, 0.5),
        p95: quantile(&samples, 0.95),
        maximum: samples[samples.len() - 1],
    }
}

fn quantile(samples: &[f64], fraction: f64) -> f64 {
    let position = ((samples.len() - 1) as f64 * fraction).round() as usize;
    samples[position]
}

struct Arguments {
    manifest: PathBuf,
    iterations: usize,
    output: Option<PathBuf>,
}

impl Arguments {
    fn parse(arguments: Vec<String>) -> Result<Self, String> {
        let mut manifest = None;
        let mut iterations = 30_usize;
        let mut output = None;
        let mut position = 0;
        while position < arguments.len() {
            let flag = &arguments[position];
            let value = arguments
                .get(position + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            match flag.as_str() {
                "--manifest" if manifest.is_none() => manifest = Some(PathBuf::from(value)),
                "--iterations" => {
                    iterations = value
                        .parse()
                        .map_err(|_| "--iterations must be an integer".to_owned())?;
                    if !(3..=1_000).contains(&iterations) {
                        return Err("--iterations must be in 3..=1000".to_owned());
                    }
                }
                "--output" if output.is_none() => output = Some(PathBuf::from(value)),
                _ => return Err(format!("unknown or duplicate argument {flag:?}")),
            }
            position += 2;
        }
        Ok(Self {
            manifest: manifest.ok_or_else(|| "--manifest is required".to_owned())?,
            iterations,
            output,
        })
    }
}

#[derive(Serialize)]
struct Distribution {
    minimum: f64,
    median: f64,
    p95: f64,
    maximum: f64,
}

#[derive(Serialize)]
struct Measurements {
    parse_lower: Distribution,
    compile_signed_package: Distribution,
    full_build_preflight: Distribution,
    environment_load: Distribution,
    direct_query: Distribution,
    prepared_hit: Distribution,
}

#[derive(Serialize)]
struct Report {
    profile: &'static str,
    iterations: usize,
    source_count: usize,
    unit_count: usize,
    relation_count: usize,
    source_bytes: usize,
    environment_bytes: usize,
    request_bytes: usize,
    correctness_mismatches: usize,
    prepared_projection_preparations: u64,
    prepared_projection_hits: u64,
    measurements_microseconds: Measurements,
    limitations: Vec<String>,
}
