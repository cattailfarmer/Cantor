use std::{env, fs, path::Path, process::ExitCode};

use cantor_ecosystem::{
    B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES,
    compile_b1_cdrive_operator_authority_ceremony_plan,
    from_b1_cdrive_operator_authority_ceremony_request_machine_form,
    to_b1_cdrive_operator_authority_ceremony_plan_machine_form,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!(
            "usage: cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan <request-file>"
        );
        return ExitCode::from(2);
    }
    match read_request(Path::new(&arguments[0])).and_then(|machine_form| {
        let request =
            from_b1_cdrive_operator_authority_ceremony_request_machine_form(&machine_form)
                .map_err(|error| error.to_string())?;
        let plan = compile_b1_cdrive_operator_authority_ceremony_plan(&request)
            .map_err(|error| error.to_string())?;
        to_b1_cdrive_operator_authority_ceremony_plan_machine_form(&request, &plan)
            .map_err(|error| error.to_string())
    }) {
        Ok(plan) => {
            println!("{plan}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn read_request(path: &Path) -> Result<String, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("request metadata failed: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > B1_CDRIVE_OPERATOR_AUTHORITY_CEREMONY_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err("request must be one bounded nonlink regular file".to_owned());
    }
    fs::read_to_string(path).map_err(|error| format!("request read failed: {error}"))
}
