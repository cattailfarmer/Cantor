use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
};

use cantor_ecosystem::sjs_repository_graph::{
    GraphFault, GraphFaultCode, compile_sjs_repository_graph_verification,
    from_change_set_machine_form, from_diff_inventory_machine_form,
};

#[derive(Debug)]
struct Cli {
    change_set: PathBuf,
    diff_inventory: PathBuf,
    output: Option<PathBuf>,
}

fn main() {
    if let Err(fault) = run() {
        eprintln!("{fault}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), GraphFault> {
    let cli = parse_args(env::args().skip(1))?;
    let inventory_bytes = fs::read(&cli.diff_inventory).map_err(|error| GraphFault {
        code: GraphFaultCode::Io,
        message: format!("failed to read diff inventory: {error}"),
    })?;
    let inventory = from_diff_inventory_machine_form(&inventory_bytes)?;
    let change_set_bytes = fs::read(&cli.change_set).map_err(|error| GraphFault {
        code: GraphFaultCode::Io,
        message: format!("failed to read change set: {error}"),
    })?;
    let change_set = from_change_set_machine_form(&change_set_bytes, &inventory)?;
    let receipt = compile_sjs_repository_graph_verification(&change_set, &inventory)?;
    let mut output = serde_json::to_vec_pretty(&receipt).map_err(|error| GraphFault {
        code: GraphFaultCode::Serialization,
        message: error.to_string(),
    })?;
    output.push(b'\n');

    if let Some(path) = cli.output {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| GraphFault {
                code: GraphFaultCode::Io,
                message: format!("failed to create output parent: {error}"),
            })?;
        }
        fs::write(&path, output).map_err(|error| GraphFault {
            code: GraphFaultCode::Io,
            message: format!("failed to write output: {error}"),
        })?;
    } else {
        io::stdout()
            .write_all(&output)
            .map_err(|error| GraphFault {
                code: GraphFaultCode::Io,
                message: format!("failed to write stdout: {error}"),
            })?;
    }
    Ok(())
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<Cli, GraphFault> {
    let mut change_set = None;
    let mut diff_inventory = None;
    let mut output = None;
    let mut arguments = arguments.into_iter();

    while let Some(argument) = arguments.next() {
        let target = match argument.as_str() {
            "--change-set" => &mut change_set,
            "--diff-inventory" => &mut diff_inventory,
            "--output" => &mut output,
            _ => {
                return Err(GraphFault {
                    code: GraphFaultCode::Cli,
                    message: format!("unknown argument: {argument}"),
                });
            }
        };
        if target.is_some() {
            return Err(GraphFault {
                code: GraphFaultCode::Cli,
                message: format!("duplicate argument: {argument}"),
            });
        }
        let value = arguments.next().ok_or_else(|| GraphFault {
            code: GraphFaultCode::Cli,
            message: format!("missing value for {argument}"),
        })?;
        *target = Some(PathBuf::from(value));
    }

    Ok(Cli {
        change_set: change_set.ok_or_else(|| GraphFault {
            code: GraphFaultCode::Cli,
            message: "missing --change-set".to_owned(),
        })?,
        diff_inventory: diff_inventory.ok_or_else(|| GraphFault {
            code: GraphFaultCode::Cli,
            message: "missing --diff-inventory".to_owned(),
        })?,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_bare_output_filename() {
        let cli = parse_args([
            "--change-set".to_owned(),
            "change-set.json".to_owned(),
            "--diff-inventory".to_owned(),
            "diff.json".to_owned(),
            "--output".to_owned(),
            "receipt.json".to_owned(),
        ])
        .unwrap();
        assert_eq!(cli.output, Some(PathBuf::from("receipt.json")));
    }

    #[test]
    fn parse_args_refuses_unknown_duplicate_and_missing_values() {
        assert_eq!(
            parse_args(["--unknown".to_owned()]).unwrap_err().code,
            GraphFaultCode::Cli
        );
        assert_eq!(
            parse_args([
                "--change-set".to_owned(),
                "one".to_owned(),
                "--change-set".to_owned(),
                "two".to_owned(),
            ])
            .unwrap_err()
            .code,
            GraphFaultCode::Cli
        );
        assert_eq!(
            parse_args(["--change-set".to_owned()]).unwrap_err().code,
            GraphFaultCode::Cli
        );
    }
}
