use std::{env, fs, io::Write, path::PathBuf};

use cantor_ecosystem::{
    sjs_repository_graph::to_diff_inventory_machine_form,
    staged_diff_acquisition::{
        AcquisitionFault, AcquisitionFaultCode, MAX_REQUEST_BYTES, acquire_staged_diff,
        from_acquisition_request_machine_form, to_acquisition_receipt_machine_form,
    },
};

#[derive(Debug, PartialEq, Eq)]
struct Cli {
    request: PathBuf,
    inventory_only: bool,
}

fn parse_cli<I>(arguments: I) -> Result<Cli, AcquisitionFault>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let mut request = None;
    let mut inventory_only = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--request" if request.is_none() => {
                let value = arguments.next().ok_or_else(|| AcquisitionFault {
                    code: AcquisitionFaultCode::Cli,
                    message: "--request requires a path".to_owned(),
                })?;
                request = Some(PathBuf::from(value));
            }
            "--inventory-only" if !inventory_only => inventory_only = true,
            _ => {
                return Err(AcquisitionFault {
                    code: AcquisitionFaultCode::Cli,
                    message: "unknown or duplicate argument".to_owned(),
                });
            }
        }
    }
    Ok(Cli {
        request: request.ok_or_else(|| AcquisitionFault {
            code: AcquisitionFaultCode::Cli,
            message: "--request is required".to_owned(),
        })?,
        inventory_only,
    })
}

fn run() -> Result<(), AcquisitionFault> {
    let cli = parse_cli(env::args())?;
    let metadata = fs::metadata(&cli.request).map_err(|error| AcquisitionFault {
        code: AcquisitionFaultCode::Io,
        message: format!("unable to inspect request: {error}"),
    })?;
    if !metadata.is_file() || metadata.len() > MAX_REQUEST_BYTES as u64 {
        return Err(AcquisitionFault {
            code: AcquisitionFaultCode::Resource,
            message: "request is absent non-file or over bound".to_owned(),
        });
    }
    let bytes = fs::read(&cli.request).map_err(|error| AcquisitionFault {
        code: AcquisitionFaultCode::Io,
        message: format!("unable to read request: {error}"),
    })?;
    let request = from_acquisition_request_machine_form(&bytes)?;
    let receipt = acquire_staged_diff(&request)?;
    let output = if cli.inventory_only {
        to_diff_inventory_machine_form(&receipt.inventory).map_err(|error| AcquisitionFault {
            code: AcquisitionFaultCode::Inventory,
            message: format!("unable to encode inventory: {error}"),
        })?
    } else {
        to_acquisition_receipt_machine_form(&request, &receipt)?
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output)
        .map_err(|error| AcquisitionFault {
            code: AcquisitionFaultCode::Io,
            message: format!("unable to write stdout: {error}"),
        })?;
    stdout.write_all(b"\n").map_err(|error| AcquisitionFault {
        code: AcquisitionFaultCode::Io,
        message: format!("unable to terminate stdout: {error}"),
    })?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        let encoded = serde_json::to_string(&error).unwrap_or_else(|_| {
            "{\"code\":\"serialization\",\"message\":\"unable to encode fault\"}".to_owned()
        });
        eprintln!("{encoded}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_accepts_exact_forms() {
        let cli = parse_cli([
            "binary".to_owned(),
            "--request".to_owned(),
            "request.json".to_owned(),
            "--inventory-only".to_owned(),
        ])
        .unwrap();
        assert_eq!(cli.request, PathBuf::from("request.json"));
        assert!(cli.inventory_only);
    }

    #[test]
    fn cli_refuses_missing_unknown_and_duplicates() {
        assert!(parse_cli(["binary".to_owned()]).is_err());
        assert!(parse_cli(["binary".to_owned(), "--unknown".to_owned(), "x".to_owned(),]).is_err());
        assert!(
            parse_cli([
                "binary".to_owned(),
                "--request".to_owned(),
                "a".to_owned(),
                "--request".to_owned(),
                "b".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_cli([
                "binary".to_owned(),
                "--request".to_owned(),
                "a".to_owned(),
                "--inventory-only".to_owned(),
                "--inventory-only".to_owned(),
            ])
            .is_err()
        );
    }
}
