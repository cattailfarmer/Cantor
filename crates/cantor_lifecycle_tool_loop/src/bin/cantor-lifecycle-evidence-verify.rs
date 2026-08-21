use std::{env, fs, path::PathBuf, process::ExitCode};

use cantor_lifecycle_tool_loop::{
    PROVIDER_INDEPENDENT_EVIDENCE_MAX_BYTES, verify_provider_independent_probe,
    verify_provider_unavailable_probe,
};

#[derive(Clone, Copy, Debug)]
enum EvidenceKind {
    ProviderIndependent,
    ProviderUnavailable,
}

#[derive(Debug)]
struct Config {
    input: PathBuf,
    output: PathBuf,
    kind: EvidenceKind,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut config = Self {
            input: PathBuf::from(
                "experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_independent_bridge_probe.json",
            ),
            output: PathBuf::from(
                "experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_independent_bridge_probe_verification.json",
            ),
            kind: EvidenceKind::ProviderIndependent,
        };
        let mut args = env::args().skip(1);
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--input" => config.input = PathBuf::from(required(&mut args, &argument)?),
                "--output" => config.output = PathBuf::from(required(&mut args, &argument)?),
                "--evidence-kind" => {
                    config.kind = match required(&mut args, &argument)?.as_str() {
                        "provider-independent" => EvidenceKind::ProviderIndependent,
                        "provider-unavailable" => EvidenceKind::ProviderUnavailable,
                        value => return Err(format!("unsupported evidence kind: {value}")),
                    }
                }
                "--help" | "-h" => {
                    println!(
                        "cantor-lifecycle-evidence-verify [--evidence-kind provider-independent|provider-unavailable] [--input PATH] [--output PATH]"
                    );
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        if config.input == config.output {
            return Err("input and output must be different files".to_owned());
        }
        Ok(config)
    }
}

fn required(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn main() -> ExitCode {
    let config = match Config::parse() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration_fault: {error}");
            return ExitCode::from(2);
        }
    };
    let metadata = match fs::metadata(&config.input) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            eprintln!("evidence_fault: input is not a regular file");
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!(
                "evidence_fault: cannot inspect {}: {error}",
                config.input.display()
            );
            return ExitCode::from(2);
        }
    };
    if metadata.len() == 0 || metadata.len() > PROVIDER_INDEPENDENT_EVIDENCE_MAX_BYTES as u64 {
        eprintln!(
            "evidence_fault: input must be 1..={PROVIDER_INDEPENDENT_EVIDENCE_MAX_BYTES} bytes; observed {}",
            metadata.len()
        );
        return ExitCode::from(2);
    }
    let source = match fs::read(&config.input) {
        Ok(source) => source,
        Err(error) => {
            eprintln!(
                "evidence_fault: cannot read {}: {error}",
                config.input.display()
            );
            return ExitCode::from(2);
        }
    };
    let encoded =
        match config.kind {
            EvidenceKind::ProviderIndependent => verify_provider_independent_probe(&source)
                .and_then(|verification| {
                    serde_json::to_vec_pretty(&verification).map_err(|error| {
                        cantor_lifecycle_tool_loop::EvidenceVerificationFault {
                            field: "verification_json".to_owned(),
                            detail: error.to_string(),
                        }
                    })
                }),
            EvidenceKind::ProviderUnavailable => verify_provider_unavailable_probe(&source)
                .and_then(|verification| {
                    serde_json::to_vec_pretty(&verification).map_err(|error| {
                        cantor_lifecycle_tool_loop::EvidenceVerificationFault {
                            field: "verification_json".to_owned(),
                            detail: error.to_string(),
                        }
                    })
                }),
        };
    let encoded = match encoded {
        Ok(encoded) => encoded,
        Err(error) => {
            eprintln!("verification_fault: {error}");
            return ExitCode::from(1);
        }
    };
    if let Some(parent) = config
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
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
        "passed: {} bytes verified; {} bytes written to {}",
        source.len(),
        encoded.len(),
        config.output.display()
    );
    ExitCode::SUCCESS
}
