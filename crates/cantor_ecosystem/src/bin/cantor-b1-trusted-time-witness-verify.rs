//! Read-only A4 verifier: exactly fourteen explicit retained input files.
use cantor_ecosystem::verify_twv_payload_paths;
use std::path::PathBuf;

fn main() {
    let paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .take(15)
        .map(PathBuf::from)
        .collect();
    match verify_twv_payload_paths(&paths) {
        Ok(receipt) => println!("{receipt}"),
        Err(error) => {
            eprintln!("A4 witness refused: {error}");
            std::process::exit(2);
        }
    }
}
