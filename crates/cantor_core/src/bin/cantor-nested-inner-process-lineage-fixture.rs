use std::io::{self, Read};

use cantor_core::{
    NESTED_INNER_PROCESS_LINEAGE_MAX_MACHINE_FORM_BYTES,
    build_nested_inner_process_lineage_evidence_bundle,
    from_nested_inner_process_lineage_request_machine_form,
    to_nested_inner_process_lineage_evidence_bundle_machine_form,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    if std::env::args().count() != 1 {
        return Err(usage().to_owned());
    }
    let mut input = String::new();
    io::stdin()
        .take((NESTED_INNER_PROCESS_LINEAGE_MAX_MACHINE_FORM_BYTES + 3) as u64)
        .read_to_string(&mut input)
        .map_err(|error| format!("stdin read failed: {error}"))?;
    let body = strip_one_line_terminator(&input);
    let request = from_nested_inner_process_lineage_request_machine_form(body)
        .map_err(|error| error.to_string())?;
    let bundle = build_nested_inner_process_lineage_evidence_bundle(&request)
        .map_err(|error| error.to_string())?;
    let output = to_nested_inner_process_lineage_evidence_bundle_machine_form(&bundle)
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

fn usage() -> &'static str {
    "usage: cantor-nested-inner-process-lineage-fixture < request.json"
}
