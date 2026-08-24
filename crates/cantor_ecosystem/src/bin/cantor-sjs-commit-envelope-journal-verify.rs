use std::{env, fs, process};

use cantor_ecosystem::sjs_commit_envelope_journal::{
    JournalFault, JournalFaultCode, compile_commit_envelope_journal_verification,
    parse_journal_json,
};

fn main() {
    match run(env::args().skip(1)) {
        Ok(output) => println!("{output}"),
        Err(fault) => {
            let fallback = format!(
                "{{\"code\":\"serialization\",\"message\":{:?}}}",
                fault.to_string()
            );
            eprintln!("{}", serde_json::to_string(&fault).unwrap_or(fallback));
            process::exit(2);
        }
    }
}

fn run(arguments: impl IntoIterator<Item = String>) -> Result<String, JournalFault> {
    let mut arguments = arguments.into_iter();
    let mut bundle_path = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--bundle" if bundle_path.is_none() => {
                bundle_path = arguments.next();
                if bundle_path.is_none() {
                    return cli_fault("--bundle requires one path");
                }
            }
            _ => return cli_fault(format!("unknown or duplicate argument: {argument}")),
        }
    }
    let bundle_path = bundle_path.ok_or_else(|| JournalFault {
        code: JournalFaultCode::Cli,
        message: "--bundle is required".to_owned(),
    })?;
    let bytes = fs::read(&bundle_path).map_err(|error| JournalFault {
        code: JournalFaultCode::Io,
        message: format!("bundle read failed: {error}"),
    })?;
    let journal = parse_journal_json(&bytes)?;
    let receipt = compile_commit_envelope_journal_verification(&journal)?;
    serde_json::to_string(&receipt).map_err(|error| JournalFault {
        code: JournalFaultCode::Serialization,
        message: format!("receipt serialization failed: {error}"),
    })
}

fn cli_fault<T>(message: impl Into<String>) -> Result<T, JournalFault> {
    Err(JournalFault {
        code: JournalFaultCode::Cli,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bundle_is_refused() {
        assert_eq!(
            run(Vec::<String>::new()).unwrap_err().code,
            JournalFaultCode::Cli
        );
    }

    #[test]
    fn unknown_and_duplicate_arguments_are_refused() {
        assert_eq!(
            run(["--output".to_owned(), "out.json".to_owned()])
                .unwrap_err()
                .code,
            JournalFaultCode::Cli
        );
        assert_eq!(
            run([
                "--bundle".to_owned(),
                "a.json".to_owned(),
                "--bundle".to_owned(),
                "b.json".to_owned(),
            ])
            .unwrap_err()
            .code,
            JournalFaultCode::Cli
        );
    }
}
