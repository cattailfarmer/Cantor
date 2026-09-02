use std::{env, io::Write, path::Path};

use cantor_ecosystem::verify_bpv_evidence_directory;

fn main() {
    if let Err(error) = run() {
        eprintln!("cantor-b1-operator-policy-governance-evidence-verify: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.len() != 1 {
        return Err("expected exactly one evidence-directory path".to_owned());
    }
    let replay = verify_bpv_evidence_directory(Path::new(&arguments[0]))
        .map_err(|error| error.to_string())?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(replay.receipt_machine_form.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|error| error.to_string())
}
