use std::io::{self, Read};

use cantor_core::{
    RUNTIME_CLOSURE_MATERIALIZATION_MAX_EVIDENCE_BYTES,
    from_runtime_closure_materialization_evidence_bundle_machine_form,
    to_runtime_closure_materialization_verification_machine_form,
    verify_runtime_closure_materialization_evidence_bundle,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    if std::env::args().count() != 1 {
        return Err(
            "usage: cantor-runtime-closure-materialization-plan-verify < evidence-bundle.json"
                .to_owned(),
        );
    }
    let mut input = String::new();
    io::stdin()
        .take((RUNTIME_CLOSURE_MATERIALIZATION_MAX_EVIDENCE_BYTES + 3) as u64)
        .read_to_string(&mut input)
        .map_err(|error| format!("stdin read failed: {error}"))?;
    let body = strip_one_line_terminator(&input);
    let bundle = from_runtime_closure_materialization_evidence_bundle_machine_form(body)
        .map_err(|error| error.to_string())?;
    let verification = verify_runtime_closure_materialization_evidence_bundle(&bundle)
        .map_err(|error| error.to_string())?;
    let output = to_runtime_closure_materialization_verification_machine_form(&verification)
        .map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn strip_one_line_terminator(value: &str) -> &str {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
}
