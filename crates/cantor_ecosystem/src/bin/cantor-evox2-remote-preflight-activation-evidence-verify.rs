use std::{env, path::Path, process};

use cantor_ecosystem::{
    to_activation_evidence_verification_machine_form,
    verify_evox2_remote_preflight_activation_evidence_directory,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let root = arguments.next().ok_or("expected one evidence directory")?;
    if arguments.next().is_some() {
        return Err("expected one evidence directory".into());
    }
    let verification =
        verify_evox2_remote_preflight_activation_evidence_directory(Path::new(&root))?;
    println!(
        "{}",
        to_activation_evidence_verification_machine_form(&verification)?
    );
    Ok(())
}
