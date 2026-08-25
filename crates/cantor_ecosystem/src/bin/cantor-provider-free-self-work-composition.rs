use std::io::{self, Read};

use cantor_ecosystem::{
    PROVIDER_FREE_SELF_WORK_COMPOSITION_MAX_MACHINE_FORM_BYTES,
    compile_provider_free_self_work_composition,
    from_provider_free_self_work_composition_receipt_machine_form,
    from_provider_free_self_work_composition_request_machine_form,
    to_provider_free_self_work_composition_receipt_machine_form,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let operation = std::env::args().nth(1).ok_or_else(|| usage().to_owned())?;
    if std::env::args().count() != 2 {
        return Err(usage().to_owned());
    }
    let mut input = String::new();
    io::stdin()
        .take((PROVIDER_FREE_SELF_WORK_COMPOSITION_MAX_MACHINE_FORM_BYTES + 1) as u64)
        .read_to_string(&mut input)
        .map_err(|error| format!("stdin read failed: {error}"))?;
    let output = match operation.as_str() {
        "compile" => {
            let request = from_provider_free_self_work_composition_request_machine_form(&input)
                .map_err(|error| error.to_string())?;
            let receipt = compile_provider_free_self_work_composition(&request)
                .map_err(|error| error.to_string())?;
            to_provider_free_self_work_composition_receipt_machine_form(&receipt)
                .map_err(|error| error.to_string())?
        }
        "verify" => {
            let receipt = from_provider_free_self_work_composition_receipt_machine_form(&input)
                .map_err(|error| error.to_string())?;
            to_provider_free_self_work_composition_receipt_machine_form(&receipt)
                .map_err(|error| error.to_string())?
        }
        _ => return Err(usage().to_owned()),
    };
    println!("{output}");
    Ok(())
}

fn usage() -> &'static str {
    "usage: cantor-provider-free-self-work-composition <compile|verify> < request-or-receipt.json"
}
