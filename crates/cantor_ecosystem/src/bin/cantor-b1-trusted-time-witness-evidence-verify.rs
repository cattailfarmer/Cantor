//! Read-only independent retained-evidence replay; exactly one directory.
use cantor_ecosystem::verify_twv_evidence_directory;
use std::path::PathBuf;

fn main() {
    let paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .take(2)
        .map(PathBuf::from)
        .collect();
    if paths.len() != 1 {
        eprintln!("A4 evidence refused: expected exactly one evidence directory");
        std::process::exit(2);
    }
    match verify_twv_evidence_directory(&paths[0]) {
        Ok(replay) => println!("{}", replay.receipt_machine_form),
        Err(error) => {
            eprintln!("A4 evidence refused: {error}");
            std::process::exit(2);
        }
    }
}
