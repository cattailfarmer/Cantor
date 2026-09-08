//! Read-only A8 verifier: exactly thirty explicit retained input files.
use cantor_ecosystem::verify_pbpc_payload_paths;
use std::path::PathBuf;

fn main() {
    let paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .take(31)
        .map(PathBuf::from)
        .collect();
    match verify_pbpc_payload_paths(&paths) {
        Ok(receipt) => println!("{receipt}"),
        Err(error) => {
            eprintln!("A8 broker-projection correspondence refused: {error}");
            std::process::exit(2);
        }
    }
}
