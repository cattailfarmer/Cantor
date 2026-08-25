use std::{env, path::Path};

use cantor_ecosystem::{to_b1_preflight_record_machine_form, verify_b1_preparation_evidence};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let evidence_root = arguments.next().ok_or_else(|| usage().to_owned())?;
    if arguments.next().is_some() {
        return Err(usage().to_owned());
    }
    let record = verify_b1_preparation_evidence(Path::new(&evidence_root))
        .map_err(|error| error.to_string())?;
    let machine_form =
        to_b1_preflight_record_machine_form(&record).map_err(|error| error.to_string())?;
    println!("{machine_form}");
    Ok(())
}

fn usage() -> &'static str {
    "usage: cantor-self-work-update-broker-b1 <preparation-evidence-directory>"
}
