//! Read-only A5 verifier: exactly nineteen explicit retained input files.
use cantor_ecosystem::verify_odcv_payload_paths;
use std::path::PathBuf;

fn main() {
    let paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .take(20)
        .map(PathBuf::from)
        .collect();
    match verify_odcv_payload_paths(&paths) {
        Ok(receipt) => println!("{receipt}"),
        Err(error) => {
            eprintln!("A5 decision chain refused: {error}");
            std::process::exit(2);
        }
    }
}
