//! Read-only A6 verifier: twenty-four explicit retained input files.
use cantor_ecosystem::verify_eocv_payload_paths;
use std::path::PathBuf;
fn main() {
    let paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .take(25)
        .map(PathBuf::from)
        .collect();
    match verify_eocv_payload_paths(&paths) {
        Ok(receipt) => println!("{receipt}"),
        Err(error) => {
            eprintln!("A6 observation correspondence refused: {error}");
            std::process::exit(2);
        }
    }
}
