use std::{env, fs, path::Path, process::ExitCode};

use cantor_ecosystem::{
    B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES,
    compile_b1_cdrive_production_broker_implementation_receipt,
    from_b1_cdrive_production_broker_implementation_request_machine_form,
    to_b1_cdrive_production_broker_implementation_receipt_machine_form,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!(
            "usage: cantor-self-work-update-broker-b1-cdrive-production-broker-implementation <request-file>"
        );
        return ExitCode::from(2);
    }
    match read_machine_form(Path::new(&arguments[0])).and_then(|machine_form| {
        let request =
            from_b1_cdrive_production_broker_implementation_request_machine_form(&machine_form)
                .map_err(|error| error.to_string())?;
        let receipt = compile_b1_cdrive_production_broker_implementation_receipt(&request)
            .map_err(|error| error.to_string())?;
        to_b1_cdrive_production_broker_implementation_receipt_machine_form(&request, &receipt)
            .map_err(|error| error.to_string())
    }) {
        Ok(receipt) => {
            println!("{receipt}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn read_machine_form(path: &Path) -> Result<String, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("request metadata failed: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1_CDRIVE_PRODUCTION_BROKER_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err("request must be one bounded nonlink regular file".to_owned());
    }
    fs::read_to_string(path).map_err(|error| format!("request read failed: {error}"))
}
