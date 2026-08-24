use std::{env, fs, io::Write, path::PathBuf};

use cantor_ecosystem::sjs_commit_placement_acquisition::{
    CommitPlacementAcquisitionRequest, MAX_PLACEMENT_REQUEST_BYTES, PlacementAcquisitionFault,
    PlacementAcquisitionFaultCode, acquire_commit_placements,
    from_placement_acquisition_request_machine_form, to_placement_acquisition_receipt_machine_form,
};

#[derive(Debug, PartialEq, Eq)]
struct Cli {
    request: PathBuf,
}

fn parse_cli<I>(arguments: I) -> Result<Cli, PlacementAcquisitionFault>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let mut request = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--request" if request.is_none() => {
                let value = arguments.next().ok_or_else(|| PlacementAcquisitionFault {
                    code: PlacementAcquisitionFaultCode::Cli,
                    message: "--request requires a path".to_owned(),
                })?;
                request = Some(PathBuf::from(value));
            }
            _ => {
                return Err(PlacementAcquisitionFault {
                    code: PlacementAcquisitionFaultCode::Cli,
                    message: "unknown or duplicate argument".to_owned(),
                });
            }
        }
    }
    Ok(Cli {
        request: request.ok_or_else(|| PlacementAcquisitionFault {
            code: PlacementAcquisitionFaultCode::Cli,
            message: "--request is required".to_owned(),
        })?,
    })
}

fn run() -> Result<(), PlacementAcquisitionFault> {
    let cli = parse_cli(env::args())?;
    let metadata = fs::metadata(&cli.request).map_err(|error| PlacementAcquisitionFault {
        code: PlacementAcquisitionFaultCode::Io,
        message: format!("unable to inspect request: {error}"),
    })?;
    if !metadata.is_file() || metadata.len() > MAX_PLACEMENT_REQUEST_BYTES as u64 {
        return Err(PlacementAcquisitionFault {
            code: PlacementAcquisitionFaultCode::Resource,
            message: "request is absent non-file or over bound".to_owned(),
        });
    }
    let bytes = fs::read(&cli.request).map_err(|error| PlacementAcquisitionFault {
        code: PlacementAcquisitionFaultCode::Io,
        message: format!("unable to read request: {error}"),
    })?;
    let request: CommitPlacementAcquisitionRequest =
        from_placement_acquisition_request_machine_form(&bytes)?;
    let receipt = acquire_commit_placements(&request)?;
    let output = to_placement_acquisition_receipt_machine_form(&request, &receipt)?;
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|error| PlacementAcquisitionFault {
            code: PlacementAcquisitionFaultCode::Io,
            message: format!("unable to write stdout: {error}"),
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
    fn cli_accepts_exact_request() {
        let cli = parse_cli([
            "binary".to_owned(),
            "--request".to_owned(),
            "request.json".to_owned(),
        ])
        .unwrap();
        assert_eq!(cli.request, PathBuf::from("request.json"));
    }

    #[test]
    fn cli_refuses_missing_unknown_and_duplicates() {
        assert!(parse_cli(["binary".to_owned()]).is_err());
        assert!(parse_cli(["binary".to_owned(), "--output".to_owned(), "x".to_owned()]).is_err());
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
    }
}
