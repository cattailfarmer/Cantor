use std::fs;
use std::io::Read;
use std::path::Path;

use cantor_core::{
    EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES, from_evox2_scratch_build_commission_machine_form,
    to_evox2_scratch_build_commission_verification_machine_form,
    verify_evox2_scratch_build_commission,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 2 || arguments[1] != "commission.json" {
        return Err(
            "usage: cantor-evox2-scratch-build-commission-verify commission.json".to_owned(),
        );
    }
    let input = read_bounded(Path::new("commission.json"))?;
    let commission = from_evox2_scratch_build_commission_machine_form(&input)
        .map_err(|error| error.to_string())?;
    let verification =
        verify_evox2_scratch_build_commission(&commission).map_err(|error| error.to_string())?;
    let output = to_evox2_scratch_build_commission_verification_machine_form(&verification)
        .map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn read_bounded(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "commission unavailable".to_owned())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES as u64
    {
        return Err("commission file boundary refused".to_owned());
    }
    let file = fs::File::open(path).map_err(|_| "commission read failed".to_owned())?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "commission read failed".to_owned())?;
    if bytes.is_empty()
        || bytes.len() > EVOX2_SCRATCH_BUILD_MAX_MACHINE_BYTES
        || bytes.len() as u64 != metadata.len()
    {
        return Err("commission file stability refused".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "commission UTF-8 refused".to_owned())
}
