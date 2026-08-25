use std::io::{self, Read};

use cantor_core::{
    SUCCEEDING_SOP_REVIEW_ADMISSION_MAX_MACHINE_FORM_BYTES, admit_succeeding_sop_review,
    from_succeeding_sop_review_admission_receipt_machine_form,
    from_succeeding_sop_review_admission_request_machine_form,
    to_succeeding_sop_review_admission_receipt_machine_form,
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
        .take((SUCCEEDING_SOP_REVIEW_ADMISSION_MAX_MACHINE_FORM_BYTES + 1) as u64)
        .read_to_string(&mut input)
        .map_err(|error| format!("stdin read failed: {error}"))?;
    let output = match operation.as_str() {
        "admit" => {
            let request = from_succeeding_sop_review_admission_request_machine_form(&input)
                .map_err(|error| error.to_string())?;
            let receipt =
                admit_succeeding_sop_review(&request).map_err(|error| error.to_string())?;
            to_succeeding_sop_review_admission_receipt_machine_form(&receipt)
                .map_err(|error| error.to_string())?
        }
        "verify" => {
            let receipt = from_succeeding_sop_review_admission_receipt_machine_form(&input)
                .map_err(|error| error.to_string())?;
            to_succeeding_sop_review_admission_receipt_machine_form(&receipt)
                .map_err(|error| error.to_string())?
        }
        _ => return Err(usage().to_owned()),
    };
    println!("{output}");
    Ok(())
}

fn usage() -> &'static str {
    "usage: cantor-succeeding-sop-review-admission <admit|verify> < request-or-receipt.json"
}
