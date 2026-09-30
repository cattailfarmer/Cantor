use std::env;
use std::fs;
use std::process::ExitCode;

use cantor_instance_contract::{
    CompatibilityStatus, compatibility_machine_form, compile_compatibility,
    parse_instance_manifest, parse_kernel_capabilities,
};

fn main() -> ExitCode {
    match run() {
        Ok(status) => status,
        Err(detail) => {
            eprintln!("{detail}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "cantor-instance-verify".to_owned());
    let kernel_path = arguments
        .next()
        .ok_or_else(|| format!("usage: {program} KERNEL.json INSTANCE.json"))?;
    let instance_path = arguments
        .next()
        .ok_or_else(|| format!("usage: {program} KERNEL.json INSTANCE.json"))?;
    if arguments.next().is_some() {
        return Err(format!("usage: {program} KERNEL.json INSTANCE.json"));
    }
    let kernel_bytes = fs::read(&kernel_path)
        .map_err(|error| format!("kernel input could not be read: {error}"))?;
    let instance_bytes = fs::read(&instance_path)
        .map_err(|error| format!("instance input could not be read: {error}"))?;
    let kernel = parse_kernel_capabilities(&kernel_bytes).map_err(|error| error.to_string())?;
    let manifest = parse_instance_manifest(&instance_bytes).map_err(|error| error.to_string())?;
    let result = compile_compatibility(&kernel, &manifest).map_err(|error| error.to_string())?;
    let output = compatibility_machine_form(&result).map_err(|error| error.to_string())?;
    println!("{}", String::from_utf8_lossy(&output));
    Ok(if result.status == CompatibilityStatus::Admitted {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}
