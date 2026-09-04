//! Read-only A7 verifier: exactly twenty-seven explicit retained input files.
use cantor_ecosystem::verify_perc_payload_paths;
use std::path::PathBuf;

fn main() {
    let paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .take(28)
        .map(PathBuf::from)
        .collect();
    match verify_perc_payload_paths(&paths) {
        Ok(receipt) => println!("{receipt}"),
        Err(error) => {
            eprintln!("A7 permit-reference correspondence refused: {error}");
            std::process::exit(2);
        }
    }
}
