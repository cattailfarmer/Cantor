use std::{
    env, fs,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cantor_lifecycle_tool_loop::{
    CustodySession, CustodyStatus, GovernedLifecycleFixture, LifecycleFixtureCase, McpArm,
    ProbeComparison, ProbePhase, ProbeRestartTrial, ProviderIndependentProbeReport,
    ProviderIndependentProbeTrial, RegistrationObservation, StatelessSession,
};
use serde::Serialize;
use serde_json::json;

const MAX_OUTPUT_BYTES: usize = 2_097_152;

#[derive(Debug)]
struct Config {
    stateless_binary: PathBuf,
    custody_binary: PathBuf,
    output: PathBuf,
    timeout: Duration,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let mut config = Self {
            stateless_binary: PathBuf::from(format!("target/debug/cantor-compiler-mcp{suffix}")),
            custody_binary: PathBuf::from(format!(
                "target/debug/cantor-compiler-custody-mcp{suffix}"
            )),
            output: PathBuf::from(
                "experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_independent_bridge_probe.json",
            ),
            timeout: Duration::from_secs(10),
        };
        let mut args = env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--stateless-mcp-bin" => {
                    config.stateless_binary = PathBuf::from(required(&mut args, &argument)?);
                }
                "--custody-mcp-bin" => {
                    config.custody_binary = PathBuf::from(required(&mut args, &argument)?);
                }
                "--output" => config.output = PathBuf::from(required(&mut args, &argument)?),
                "--timeout-seconds" => {
                    let seconds = required(&mut args, &argument)?
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?;
                    if !(1..=60).contains(&seconds) {
                        return Err("timeout must be 1..=60 seconds".to_owned());
                    }
                    config.timeout = Duration::from_secs(seconds);
                }
                "--help" | "-h" => {
                    println!(
                        "cantor-lifecycle-bridge-probe [--stateless-mcp-bin PATH] \
                         [--custody-mcp-bin PATH] [--output PATH] [--timeout-seconds 1..60]"
                    );
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        for (label, path) in [
            ("stateless MCP binary", &config.stateless_binary),
            ("custody MCP binary", &config.custody_binary),
        ] {
            if !path.is_file() {
                return Err(format!("{label} is absent: {}", path.display()));
            }
        }
        Ok(config)
    }
}

fn required(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeFault {
    kind: String,
    detail: String,
}

impl ProbeFault {
    fn new(kind: &str, detail: impl ToString) -> Self {
        Self {
            kind: kind.to_owned(),
            detail: detail.to_string().chars().take(1_000).collect(),
        }
    }
}

fn main() -> ExitCode {
    match std::thread::Builder::new()
        .name("cantor-lifecycle-bridge-probe".to_owned())
        .stack_size(16 * 1_024 * 1_024)
        .spawn(run_on_bounded_stack)
    {
        Ok(worker) => match worker.join() {
            Ok(exit) => exit,
            Err(_) => {
                eprintln!("internal_fault: orchestration thread panicked");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("internal_fault: cannot start orchestration thread: {error}");
            ExitCode::from(2)
        }
    }
}

fn run_on_bounded_stack() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("internal_fault: cannot create runtime: {error}");
            return ExitCode::from(2);
        }
    };
    runtime.block_on(run_main())
}

async fn run_main() -> ExitCode {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration_fault: {error}");
            return ExitCode::from(2);
        }
    };
    let started = unix_time_ms();
    let (report, passed) = match run(&config, started).await {
        Ok(report) => (
            serde_json::to_value(report).expect("typed probe report must encode"),
            true,
        ),
        Err(fault) => (
            json!({
                "probe": "cantor_lifecycle_bridge_probe",
                "status": "failed",
                "started_unix_ms": started,
                "finished_unix_ms": unix_time_ms(),
                "fault": fault,
                "provider_contacted": false,
                "trials": []
            }),
            false,
        ),
    };
    let encoded = match serde_json::to_vec_pretty(&report) {
        Ok(encoded) if encoded.len() <= MAX_OUTPUT_BYTES => encoded,
        Ok(encoded) => {
            eprintln!(
                "evidence_fault: report contains {} bytes; maximum is {MAX_OUTPUT_BYTES}",
                encoded.len()
            );
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("evidence_fault: {error}");
            return ExitCode::from(2);
        }
    };
    if let Some(parent) = config.output.parent()
        && let Err(error) = fs::create_dir_all(parent)
    {
        eprintln!(
            "evidence_fault: cannot create {}: {error}",
            parent.display()
        );
        return ExitCode::from(2);
    }
    if let Err(error) = fs::write(&config.output, &encoded) {
        eprintln!(
            "evidence_fault: cannot write {}: {error}",
            config.output.display()
        );
        return ExitCode::from(2);
    }
    println!(
        "{}: {} bytes written to {}",
        if passed { "passed" } else { "failed" },
        encoded.len(),
        config.output.display()
    );
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

async fn run(
    config: &Config,
    started_unix_ms: u128,
) -> Result<ProviderIndependentProbeReport, ProbeFault> {
    let fixtures = [
        GovernedLifecycleFixture::load(LifecycleFixtureCase::Valid)
            .map_err(|error| ProbeFault::new("fixture_fault", error))?,
        GovernedLifecycleFixture::load(LifecycleFixtureCase::LifecycleRefused)
            .map_err(|error| ProbeFault::new("fixture_fault", error))?,
    ];
    let stateless = StatelessSession::open(&config.stateless_binary, config.timeout)
        .await
        .map_err(|error| ProbeFault::new("stateless_open_fault", error))?;
    let mut custody = match CustodySession::open(&config.custody_binary, config.timeout).await {
        Ok(custody) => custody,
        Err(error) => {
            let _ = stateless.close().await;
            return Err(ProbeFault::new("custody_open_fault", error));
        }
    };
    let mut registrations: Vec<RegistrationObservation> = Vec::new();
    for fixture in &fixtures {
        match custody.register(fixture).await {
            Ok(registration) => registrations.push(registration),
            Err(error) => {
                let _ = stateless.close().await;
                let _ = custody.close().await;
                return Err(ProbeFault::new("registration_fault", error));
            }
        }
    }
    let restart_handle = custody
        .handle(LifecycleFixtureCase::Valid)
        .cloned()
        .ok_or_else(|| ProbeFault::new("restart_handle_fault", "missing valid handle"))?;

    let mut trials = Vec::new();
    let mut sequence = 0;
    for round in 0..2 {
        for fixture in &fixtures {
            for arm in [McpArm::Stateless, McpArm::VolatileCustody] {
                let observation = match arm {
                    McpArm::Stateless => stateless.validate(fixture).await,
                    McpArm::VolatileCustody => custody.validate(fixture).await,
                }
                .map_err(|error| ProbeFault::new("validation_fault", error))?;
                trials.push(ProviderIndependentProbeTrial {
                    sequence,
                    phase: if round == 0 {
                        ProbePhase::FirstCall
                    } else {
                        ProbePhase::SteadyState
                    },
                    fixture_case: fixture.case,
                    observation,
                });
                sequence += 1;
            }
        }
    }
    stateless
        .close()
        .await
        .map_err(|error| ProbeFault::new("stateless_shutdown_fault", error))?;
    custody
        .close()
        .await
        .map_err(|error| ProbeFault::new("custody_shutdown_fault", error))?;

    let restarted = CustodySession::open(&config.custody_binary, config.timeout)
        .await
        .map_err(|error| ProbeFault::new("restart_open_fault", error))?;
    let restart_response = restarted
        .validate_raw_handle(&restart_handle)
        .await
        .map_err(|error| ProbeFault::new("restart_validation_fault", error))?;
    let restart_refused = restart_response.status == CustodyStatus::Refused
        && restart_response.lifecycle_response.is_none();
    restarted
        .close()
        .await
        .map_err(|error| ProbeFault::new("restart_shutdown_fault", error))?;
    if !restart_refused {
        return Err(ProbeFault::new(
            "restart_semantic_fault",
            format!("unexpected restart response: {restart_response:?}"),
        ));
    }

    let stateless_bytes = transport_argument_bytes(&trials, McpArm::Stateless);
    let custody_bytes = transport_argument_bytes(&trials, McpArm::VolatileCustody);
    let compression_basis_points = custody_bytes
        .saturating_mul(10_000)
        .checked_div(stateless_bytes)
        .unwrap_or(0);
    Ok(ProviderIndependentProbeReport {
        probe: "cantor_lifecycle_bridge_probe".to_owned(),
        contract: "Cantor_Live_Lifecycle_Tool_Loop_Measurement_P0.sop".to_owned(),
        status: "passed".to_owned(),
        started_unix_ms,
        finished_unix_ms: unix_time_ms(),
        provider_contacted: false,
        private_reasoning_recorded: false,
        custody_registrations_outside_steady_state: registrations,
        comparison: ProbeComparison {
            stateless_transport_argument_bytes: stateless_bytes,
            custody_transport_argument_bytes: custody_bytes,
            transport_bytes_saved: stateless_bytes.saturating_sub(custody_bytes),
            custody_to_stateless_argument_basis_points: compression_basis_points,
        },
        restart_trial: ProbeRestartTrial {
            status: "passed".to_owned(),
            old_handle_refused: true,
            response: restart_response,
            excluded_from_steady_state: true,
            persistence_claimed: false,
        },
        trials,
    })
}

fn transport_argument_bytes(trials: &[ProviderIndependentProbeTrial], arm: McpArm) -> usize {
    trials
        .iter()
        .filter(|trial| trial.observation.arm == arm)
        .map(|trial| trial.observation.argument_bytes)
        .sum()
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
