use std::{env, fs, path::Path, process::ExitCode};

use cantor_ecosystem::{
    B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES,
    from_b1_cdrive_operator_decision_envelope_machine_form,
    from_b1_cdrive_operator_decision_policy_machine_form,
    from_b1_cdrive_operator_decision_request_machine_form,
    to_b1_cdrive_operator_decision_verification_machine_form, verify_b1_cdrive_operator_decision,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 3 {
        eprintln!(
            "usage: cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-decision-verify <request-file> <policy-file> <decision-file>"
        );
        return ExitCode::from(2);
    }
    match read_bounded(Path::new(&arguments[1]), "policy")
        .and_then(|policy_text| {
            from_b1_cdrive_operator_decision_policy_machine_form(&policy_text)
                .map_err(|error| error.to_string())
        })
        .and_then(|policy| {
            read_bounded(Path::new(&arguments[0]), "request").and_then(|request_text| {
                from_b1_cdrive_operator_decision_request_machine_form(&policy, &request_text)
                    .map(|request| (policy, request))
                    .map_err(|error| error.to_string())
            })
        })
        .and_then(|(policy, request)| {
            read_bounded(Path::new(&arguments[2]), "decision").and_then(|decision_text| {
                from_b1_cdrive_operator_decision_envelope_machine_form(
                    &request,
                    &policy,
                    &decision_text,
                )
                .map(|decision| (policy, request, decision))
                .map_err(|error| error.to_string())
            })
        })
        .and_then(|(policy, request, decision)| {
            let receipt = verify_b1_cdrive_operator_decision(&request, &policy, &decision)
                .map_err(|error| error.to_string())?;
            to_b1_cdrive_operator_decision_verification_machine_form(
                &request, &policy, &decision, &receipt,
            )
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

fn read_bounded(path: &Path, label: &str) -> Result<String, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{label} metadata failed: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > B1_CDRIVE_OPERATOR_DECISION_MAX_MACHINE_FORM_BYTES as u64
    {
        return Err(format!(
            "{label} must be one bounded nonlink nonreparse regular file"
        ));
    }
    fs::read_to_string(path).map_err(|error| format!("{label} read failed: {error}"))
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
