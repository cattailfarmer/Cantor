use std::{env, fs, path::Path, process::ExitCode};

use cantor_ecosystem::{
    B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES,
    compile_b1_cdrive_production_preparation_commission_proposal,
    from_b1_cdrive_production_preparation_commission_proposal_request_machine_form,
    to_b1_cdrive_production_preparation_commission_proposal_machine_form,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 1 {
        eprintln!(
            "usage: cantor-self-work-update-broker-b1-cdrive-production-preparation-commission-proposal <request-file>"
        );
        return ExitCode::from(2);
    }
    match read_request(Path::new(&arguments[0])).and_then(|machine_form| {
        let request =
            from_b1_cdrive_production_preparation_commission_proposal_request_machine_form(
                &machine_form,
            )
            .map_err(|error| error.to_string())?;
        let proposal = compile_b1_cdrive_production_preparation_commission_proposal(&request)
            .map_err(|error| error.to_string())?;
        to_b1_cdrive_production_preparation_commission_proposal_machine_form(&request, &proposal)
            .map_err(|error| error.to_string())
    }) {
        Ok(proposal) => {
            println!("{proposal}");
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
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len()
            > B1_CDRIVE_PRODUCTION_PREPARATION_COMMISSION_PROPOSAL_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err("request must be one bounded nonlink nonreparse regular file".to_owned());
    }
    fs::read_to_string(path).map_err(|error| format!("request read failed: {error}"))
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
