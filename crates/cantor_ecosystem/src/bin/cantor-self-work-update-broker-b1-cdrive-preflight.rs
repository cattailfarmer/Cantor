use std::{env, path::Path, process::ExitCode};

use cantor_ecosystem::{
    to_b1_cdrive_preflight_receipt_machine_form, verify_b1_cdrive_preflight_evidence,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!("usage: cantor-self-work-update-broker-b1-cdrive-preflight <evidence-directory>");
        return ExitCode::from(2);
    }
    match verify_b1_cdrive_preflight_evidence(Path::new(&arguments[0]))
        .and_then(|receipt| to_b1_cdrive_preflight_receipt_machine_form(&receipt))
    {
        Ok(machine_form) => {
            println!("{machine_form}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
