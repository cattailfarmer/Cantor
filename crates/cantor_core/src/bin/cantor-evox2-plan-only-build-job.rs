use std::fs;
use std::io::Read;
use std::path::Path;

use cantor_core::{
    EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES, compile_evox2_build_plan,
    from_evox2_build_plan_request_machine_form, to_evox2_build_plan_machine_form,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[1] != "request.json" {
        return Err("usage: cantor-evox2-plan-only-build-job request.json".to_owned());
    }
    let path = Path::new("request.json");
    let bytes = read_bounded(path, EVOX2_BUILD_PLAN_MAX_REQUEST_BYTES)?;
    let body = std::str::from_utf8(&bytes).map_err(|_| "request UTF-8 refused".to_owned())?;
    let request =
        from_evox2_build_plan_request_machine_form(body).map_err(|error| error.to_string())?;
    let plan = compile_evox2_build_plan(&request).map_err(|error| error.to_string())?;
    let output = to_evox2_build_plan_machine_form(&plan).map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "request unavailable".to_owned())?;
    if !is_single_regular_file(&metadata) || metadata.len() == 0 || metadata.len() > maximum as u64
    {
        return Err("request file boundary refused".to_owned());
    }
    let file = fs::File::open(path).map_err(|_| "request read failed".to_owned())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "request read failed".to_owned())?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
        return Err("request file stability refused".to_owned());
    }
    Ok(bytes)
}

fn is_single_regular_file(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && !metadata.file_type().is_symlink()
}
