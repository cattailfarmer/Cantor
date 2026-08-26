use std::{env, path::Path, process::ExitCode};

use cantor_ecosystem::{
    to_cdrive_worktree_preparation_simulation_receipt_machine_form,
    verify_cdrive_worktree_preparation_evidence,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!(
            "usage: cantor-self-work-update-broker-b1-cdrive-worktree-preparation-evidence-verify <evidence-directory>"
        );
        return ExitCode::from(2);
    }
    match verify_cdrive_worktree_preparation_evidence(Path::new(&arguments[0])).and_then(
        |receipt| to_cdrive_worktree_preparation_simulation_receipt_machine_form(&receipt),
    ) {
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
