use std::fs;
use std::io::Read;
use std::path::Path;

use cantor_core::{
    EVOX2_BUILD_PLAN_MAX_PLAN_BYTES, EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES,
    from_evox2_build_plan_machine_form, from_evox2_build_plan_request_machine_form,
    to_evox2_build_plan_verification_machine_form, verify_evox2_build_plan,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 3
        || arguments[1] != "request.json"
        || !matches!(arguments[2].as_str(), "plan-1.json" | "plan-2.json")
    {
        return Err(
            "usage: cantor-evox2-plan-only-build-job-verify request.json <plan-1.json|plan-2.json>"
                .to_owned(),
        );
    }
    let request = read_bounded(
        Path::new("request.json"),
        EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES,
    )?;
    let plan = read_bounded(Path::new(&arguments[2]), EVOX2_BUILD_PLAN_MAX_PLAN_BYTES)?;
    let request =
        from_evox2_build_plan_request_machine_form(&request).map_err(|error| error.to_string())?;
    let plan = from_evox2_build_plan_machine_form(&plan).map_err(|error| error.to_string())?;
    let verification =
        verify_evox2_build_plan(&request, &plan).map_err(|error| error.to_string())?;
    let output = to_evox2_build_plan_verification_machine_form(&verification)
        .map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "input unavailable".to_owned())?;
    if !is_single_regular_file(&metadata) || metadata.len() == 0 || metadata.len() > maximum as u64
    {
        return Err("input file boundary refused".to_owned());
    }
    let file = fs::File::open(path).map_err(|_| "input read failed".to_owned())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "input read failed".to_owned())?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err("input file stability refused".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "input UTF-8 refused".to_owned())
}

fn is_single_regular_file(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && !metadata.file_type().is_symlink()
}
