use std::env;
use std::process::ExitCode;

use cantor_instance_contract::fixture::{
    eclipse_instance_candidate_fixture, eclipse_kernel_candidate_fixture, published_kernel_fixture,
};

fn main() -> ExitCode {
    let mut arguments = env::args();
    let program = arguments
        .next()
        .unwrap_or_else(|| "cantor-instance-fixture".to_owned());
    let Some(kind) = arguments.next() else {
        eprintln!("usage: {program} kernel|eclipse|eclipse-kernel-candidate");
        return ExitCode::from(1);
    };
    if arguments.next().is_some() {
        eprintln!("usage: {program} kernel|eclipse|eclipse-kernel-candidate");
        return ExitCode::from(1);
    }
    let output = match kind.as_str() {
        "kernel" => serde_json::to_string_pretty(&published_kernel_fixture()),
        "eclipse" => serde_json::to_string_pretty(&eclipse_instance_candidate_fixture()),
        "eclipse-kernel-candidate" => {
            serde_json::to_string_pretty(&eclipse_kernel_candidate_fixture())
        }
        _ => {
            eprintln!("unknown fixture kind: {kind}");
            return ExitCode::from(1);
        }
    };
    match output {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fixture serialization failed: {error}");
            ExitCode::from(1)
        }
    }
}
