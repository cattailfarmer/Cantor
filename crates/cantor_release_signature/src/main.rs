use std::{
    env, fs,
    io::{self, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use cantor_release_signature::{
    MAX_BUNDLE_BYTES, MAX_ENVELOPE_BYTES, MAX_EVIDENCE_BYTES, MAX_POLICY_BYTES,
    verify_release_signature_bytes,
};

#[derive(Debug)]
struct Config {
    bundle: PathBuf,
    bundle_evidence: PathBuf,
    policy: PathBuf,
    envelope: PathBuf,
}

enum ParseDisposition {
    Run(Config),
    Help,
}

fn main() -> ExitCode {
    let config = match parse_config() {
        Ok(ParseDisposition::Run(config)) => config,
        Ok(ParseDisposition::Help) => {
            println!(
                "cantor-release-verify --bundle PATH --bundle-evidence PATH --policy PATH --envelope PATH"
            );
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("invocation_fault: {error}");
            return ExitCode::from(2);
        }
    };
    let paths = [
        (&config.bundle, "bundle", MAX_BUNDLE_BYTES),
        (
            &config.bundle_evidence,
            "bundle evidence",
            MAX_EVIDENCE_BYTES,
        ),
        (&config.policy, "policy", MAX_POLICY_BYTES),
        (&config.envelope, "envelope", MAX_ENVELOPE_BYTES),
    ];
    let mut canonical = Vec::new();
    let mut inputs = Vec::new();
    for (path, label, maximum) in paths {
        let (bytes, identity) = match read_physical_file(path, label, maximum) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("input_fault: {error}");
                return ExitCode::from(2);
            }
        };
        if canonical.contains(&identity) {
            eprintln!("input_fault: input files must be distinct");
            return ExitCode::from(2);
        }
        canonical.push(identity);
        inputs.push(bytes);
    }
    let receipt =
        match verify_release_signature_bytes(&inputs[0], &inputs[1], &inputs[2], &inputs[3]) {
            Ok(receipt) => receipt,
            Err(error) => {
                eprintln!("verification_fault: {error}");
                return ExitCode::from(3);
            }
        };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if serde_json::to_writer(&mut output, &receipt).is_err() || writeln!(output).is_err() {
        eprintln!("serialization_fault: receipt serialization failed");
        return ExitCode::from(70);
    }
    ExitCode::SUCCESS
}

fn parse_config() -> Result<ParseDisposition, String> {
    let mut bundle = None;
    let mut bundle_evidence = None;
    let mut policy = None;
    let mut envelope = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if matches!(argument.as_str(), "--help" | "-h") {
            if bundle.is_some()
                || bundle_evidence.is_some()
                || policy.is_some()
                || envelope.is_some()
                || arguments.next().is_some()
            {
                return Err("help must be the only argument".to_owned());
            }
            return Ok(ParseDisposition::Help);
        }
        let target = match argument.as_str() {
            "--bundle" => &mut bundle,
            "--bundle-evidence" => &mut bundle_evidence,
            "--policy" => &mut policy,
            "--envelope" => &mut envelope,
            _ => return Err(format!("unknown argument: {argument}")),
        };
        if target.is_some() {
            return Err(format!("duplicate argument: {argument}"));
        }
        let value = arguments
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{argument} requires a nonempty path"))?;
        *target = Some(PathBuf::from(value));
    }
    Ok(ParseDisposition::Run(Config {
        bundle: bundle.ok_or("--bundle is required")?,
        bundle_evidence: bundle_evidence.ok_or("--bundle-evidence is required")?,
        policy: policy.ok_or("--policy is required")?,
        envelope: envelope.ok_or("--envelope is required")?,
    }))
}

fn read_physical_file(
    path: &PathBuf,
    label: &str,
    maximum: usize,
) -> Result<(Vec<u8>, PathBuf), String> {
    let before = fs::symlink_metadata(path).map_err(|_| format!("{label} is unavailable"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(format!("{label} must be one physical regular file"));
    }
    if before.len() == 0 || before.len() > maximum as u64 {
        return Err(format!("{label} byte bound differs"));
    }
    let canonical_before =
        fs::canonicalize(path).map_err(|_| format!("{label} identity is unavailable"))?;
    let mut file = fs::File::open(path).map_err(|_| format!("{label} cannot be opened"))?;
    let opened = file
        .metadata()
        .map_err(|_| format!("{label} open identity is unavailable"))?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err(format!("{label} changed while being read"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("{label} cannot be read"))?;
    let after =
        fs::symlink_metadata(path).map_err(|_| format!("{label} changed while being read"))?;
    let canonical_after =
        fs::canonicalize(path).map_err(|_| format!("{label} changed while being read"))?;
    let opened_after = file
        .metadata()
        .map_err(|_| format!("{label} changed while being read"))?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || canonical_before != canonical_after
        || before.len() != after.len()
        || opened.len() != opened_after.len()
        || bytes.len() as u64 != opened.len()
    {
        return Err(format!("{label} changed while being read"));
    }
    Ok((bytes, canonical_after))
}
