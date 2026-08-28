use std::{env, path::Path, process::ExitCode};

use cantor_ecosystem::{
    to_b1oapr_evidence_verification_machine_form, verify_b1oapr_evidence_directory,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!(
            "usage: cantor-b1-operator-authority-packet-evidence-verify <evidence-directory>"
        );
        return ExitCode::from(2);
    }
    match verify_b1oapr_evidence_directory(Path::new(&arguments[0]))
        .and_then(|evidence| to_b1oapr_evidence_verification_machine_form(&evidence))
    {
        Ok(evidence) => {
            println!("{evidence}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
