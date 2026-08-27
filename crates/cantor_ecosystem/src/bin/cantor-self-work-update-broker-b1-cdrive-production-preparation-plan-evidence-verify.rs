use std::{env, path::Path, process::ExitCode};

use cantor_ecosystem::{
    to_b1_cdrive_production_preparation_evidence_verification_machine_form,
    verify_b1_cdrive_production_preparation_evidence_directory,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!(
            "usage: cantor-self-work-update-broker-b1-cdrive-production-preparation-plan-evidence-verify <evidence-directory>"
        );
        return ExitCode::from(2);
    }
    match verify_b1_cdrive_production_preparation_evidence_directory(Path::new(&arguments[0]))
        .and_then(|verification| {
            to_b1_cdrive_production_preparation_evidence_verification_machine_form(&verification)
        }) {
        Ok(verification) => {
            println!("{verification}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
